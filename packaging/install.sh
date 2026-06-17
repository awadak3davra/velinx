#!/bin/sh
# WakeRoute (wakeroute) installer for Entware.
#
#   Usage:  ./install.sh [arch]
#   arch is auto-detected from the device when omitted.
#   Valid arches: mipsle | mips | arm | arm64 | amd64
#
# Idempotent: re-running upgrades the binary in place and restarts the service.
set -e

OPT=/opt
SBIN="$OPT/sbin"
INITD="$OPT/etc/init.d"
ETC="$OPT/etc/wakeroute"
VAR="$OPT/var/wakeroute"
SRC="$(cd "$(dirname "$0")" && pwd)"

say() { echo "[wakeroute] $*"; }
die() { echo "[wakeroute] ERROR: $*" >&2; exit 1; }

[ -d "$OPT" ] || die "Entware /opt not found - install Entware first."

# --- detect architecture ---------------------------------------------------
detect_arch() {
  case "$(uname -m)" in
    armv7l|armv6l|arm) echo arm; return;;
    aarch64|arm64)     echo arm64; return;;
    x86_64|amd64)      echo amd64; return;;
    mips|mips64)
      # endianness from the ELF EI_DATA byte (offset 5: 1=LE, 2=BE) of busybox
      bb="$(command -v busybox 2>/dev/null || echo /bin/busybox)"
      d="$(dd if="$bb" bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')"
      [ "$d" = "1" ] && echo mipsle || echo mips
      return;;
  esac
  echo unknown
}

ARCH="${1:-$(detect_arch)}"
[ "$ARCH" = "unknown" ] && die "could not detect arch (uname -m=$(uname -m)); pass one explicitly"
say "architecture: $ARCH"

BIN="$SRC/wakeroute-$ARCH"
[ -f "$BIN" ] || BIN="$SRC/wakeroute"
[ -f "$BIN" ] || die "binary not found - expected $SRC/wakeroute-$ARCH (or $SRC/wakeroute)"

# --- install ---------------------------------------------------------------
mkdir -p "$SBIN" "$INITD" "$ETC" "$VAR"

if [ -x "$INITD/S99wakeroute" ]; then
  say "stopping existing service"
  "$INITD/S99wakeroute" stop 2>/dev/null || true
fi

say "installing binary -> $SBIN/wakeroute"
cp "$BIN" "$SBIN/wakeroute.new"
chmod 0755 "$SBIN/wakeroute.new"
# keep a SINGLE rolling backup of the previous binary for rollback; overwriting
# it each install means it never accumulates (cf. ad-hoc .bak-<commit> cruft).
if [ -f "$SBIN/wakeroute" ]; then
  cp "$SBIN/wakeroute" "$SBIN/wakeroute.bak"
fi
mv "$SBIN/wakeroute.new" "$SBIN/wakeroute"          # atomic replace

if [ -f "$SRC/S99wakeroute" ]; then
  say "installing init script -> $INITD/S99wakeroute"
  cp "$SRC/S99wakeroute" "$INITD/S99wakeroute"
  chmod 0755 "$INITD/S99wakeroute"
fi

if [ ! -f "$ETC/config.json" ]; then
  say "writing default config -> $ETC/config.json"
  cat > "$ETC/config.json" <<'JSON'
{
  "listen": ":8088",
  "data_dir": "/opt/var/wakeroute",
  "demo": false,
  "ports": { "ui": 8088, "clash": 9090, "dns": 5353, "mixed": 7890 },
  "clash": { "controller": "127.0.0.1:9090", "secret": "" },
  "singbox": { "bin": "/opt/sbin/sing-box", "config": "/opt/etc/wakeroute/singbox.json" }
}
JSON
else
  say "keeping existing config $ETC/config.json"
fi

# --- sing-box dependency ----------------------------------------------------
if [ ! -x /opt/sbin/sing-box ] && ! command -v sing-box >/dev/null 2>&1; then
  say "NOTE: sing-box not found. wakeroute serves the UI without it, but cannot Apply"
  say "      a config until sing-box is present at /opt/sbin/sing-box."
  say "      Try:  opkg install sing-box"
  say "      Or download the '$ARCH' build from"
  say "      https://github.com/SagerNet/sing-box/releases  ->  /opt/sbin/sing-box"
fi

# --- start ------------------------------------------------------------------
if [ -x "$INITD/S99wakeroute" ]; then
  say "starting service"
  "$INITD/S99wakeroute" start || say "start returned non-zero; check '$INITD/S99wakeroute start'"
fi

IP="$(ip route get 1 2>/dev/null | awk '{print $7; exit}')"
[ -z "$IP" ] && IP="$(uname -n 2>/dev/null)"
say "done -> open  http://${IP:-<router-ip>}:8088"
