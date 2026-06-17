#!/bin/sh
# WakeRoute (wakeroute) installer for OpenWrt 25.x (procd / apk / nftables).
#
#   Usage:  ./install.sh [arch]
#   arch is only used to pick the binary file name; auto-detected when omitted.
#   Valid arches: mipsle | mips | arm | arm64 | amd64
#
# Self-contained: this script installs nothing via apk/opkg. The wakeroute
# binary is static, so we only place files + register the procd service.
#
# Idempotent: re-running upgrades the binary in place and restarts the service.
#
# POSIX sh / busybox-safe: no bashisms, no base64, no scp, no nohup, no `od -A`.
set -e

# --- native OpenWrt paths --------------------------------------------------
SBIN=/usr/sbin                       # wakeroute binary
INITD=/etc/init.d                    # procd init script
ETC=/etc/wakeroute                   # config dir
VAR=/var/lib/wakeroute               # runtime state (data_dir)
SRC="$(cd "$(dirname "$0")" && pwd)" # dir this script lives in

say() { echo "[wakeroute] $*"; }
die() { echo "[wakeroute] ERROR: $*" >&2; exit 1; }

# Sanity: this is an OpenWrt-only installer.
[ -f /etc/rc.common ] || die "/etc/rc.common not found - this installer is for OpenWrt (procd)."

# --- detect architecture (binary file-name suffix only) --------------------
detect_arch() {
	case "$(uname -m)" in
		armv7l|armv6l|arm) echo arm; return;;
		aarch64|arm64)     echo arm64; return;;
		x86_64|amd64)      echo amd64; return;;
		mips|mips64)
			# Endianness from the ELF EI_DATA byte (offset 5: 1=LE, 2=BE).
			# busybox has no `od -A`; use `-t u1` plus head to stay portable.
			bb="$(command -v busybox 2>/dev/null || echo /bin/busybox)"
			d="$(dd if="$bb" bs=1 skip=5 count=1 2>/dev/null | od -t u1 | head -n1 | tr -s ' ' | cut -d' ' -f2)"
			[ "$d" = "1" ] && echo mipsle || echo mips
			return;;
	esac
	echo unknown
}

ARCH="${1:-$(detect_arch)}"
[ "$ARCH" = "unknown" ] && die "could not detect arch (uname -m=$(uname -m)); pass one explicitly"
say "architecture: $ARCH"

# Prefer the arch-suffixed binary; fall back to a plain 'wakeroute'.
BIN="$SRC/wakeroute-$ARCH"
[ -f "$BIN" ] || BIN="$SRC/wakeroute"
[ -f "$BIN" ] || die "binary not found - expected $SRC/wakeroute-$ARCH (or $SRC/wakeroute)"

# --- create directories ----------------------------------------------------
mkdir -p "$ETC" "$VAR"

# --- stop any running instance before swapping the binary ------------------
if [ -x "$INITD/wakeroute" ]; then
	say "stopping existing service"
	"$INITD/wakeroute" stop 2>/dev/null || true
fi

# --- install binary (atomic: copy to .new then mv) -------------------------
say "installing binary -> $SBIN/wakeroute"
cp "$BIN" "$SBIN/wakeroute.new"
chmod 0755 "$SBIN/wakeroute.new"
# keep a SINGLE rolling backup of the previous binary for rollback; overwriting
# it each install means it never accumulates (cf. ad-hoc .bak-<commit> cruft).
if [ -f "$SBIN/wakeroute" ]; then
	cp "$SBIN/wakeroute" "$SBIN/wakeroute.bak"
fi
mv "$SBIN/wakeroute.new" "$SBIN/wakeroute"

# --- install procd init script ---------------------------------------------
[ -f "$SRC/wakeroute.init" ] || die "wakeroute.init not found next to this installer"
say "installing init script -> $INITD/wakeroute"
cp "$SRC/wakeroute.init" "$INITD/wakeroute.new"
chmod 0755 "$INITD/wakeroute.new"
mv "$INITD/wakeroute.new" "$INITD/wakeroute"

# --- seed config (only if absent) ------------------------------------------
# Field names match internal/config/config.go exactly. The binary fills any
# omitted fields from its built-in defaults, but we write a complete, native
# config so the on-disk file is self-documenting and uses OpenWrt paths.
if [ ! -f "$ETC/config.json" ]; then
	say "writing default config -> $ETC/config.json"
	cat > "$ETC/config.json" <<JSON
{
  "listen": ":8088",
  "data_dir": "$VAR",
  "demo": false,
  "ports": { "ui": 8088, "clash": 9090, "dns": 5353, "mixed": 7890 },
  "clash": { "controller": "127.0.0.1:9090", "secret": "" },
  "singbox": { "bin": "/usr/bin/sing-box", "config": "$ETC/singbox.json" },
  "failsafe": { "target": "1.1.1.1", "auto_reboot": false }
}
JSON
	chmod 0600 "$ETC/config.json"
else
	say "keeping existing config $ETC/config.json"
fi

# --- sing-box dependency note (non-fatal) ----------------------------------
# The UI serves fine without sing-box; you just cannot Apply a proxy config
# until the engine binary is present at the path in config.json -> singbox.bin.
if [ ! -x /usr/bin/sing-box ] && ! command -v sing-box >/dev/null 2>&1; then
	say "NOTE: sing-box not found. wakeroute serves the UI, but cannot Apply a"
	say "      config until sing-box exists at /usr/bin/sing-box."
	say "      Install it (apk add sing-box) or drop the '$ARCH' build from"
	say "      https://github.com/SagerNet/sing-box/releases -> /usr/bin/sing-box"
fi

# --- enable (boot symlink) + start -----------------------------------------
say "enabling service (boot start)"
"$INITD/wakeroute" enable || say "enable returned non-zero; check '$INITD/wakeroute enable'"

say "starting service"
"$INITD/wakeroute" start || say "start returned non-zero; check 'logread -e wakeroute'"

# --- report URL ------------------------------------------------------------
# busybox has no `ip -br`; pull the source address from `ip route get`.
IP="$(ip route get 1 2>/dev/null | awk '{print $7; exit}')"
[ -z "$IP" ] && IP="$(uname -n 2>/dev/null)"
say "done -> open  http://${IP:-<router-ip>}:8088"
say "logs: logread -e wakeroute   |   status: $INITD/wakeroute status"
