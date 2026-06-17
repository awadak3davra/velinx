#!/bin/sh
# Remove WakeRoute (wakeroute) from OpenWrt. Keeps your config by default.
#
#   ./uninstall.sh           # stop+disable service, remove binary + init script,
#                            # keep /etc/wakeroute and /var/lib/wakeroute
#   ./uninstall.sh --purge   # also remove config + runtime state
#
# POSIX sh / busybox-safe: no bashisms.
set -e

SBIN=/usr/sbin
INITD=/etc/init.d
ETC=/etc/wakeroute
VAR=/var/lib/wakeroute

say() { echo "[wakeroute] $*"; }

# --- stop + disable the procd service --------------------------------------
if [ -x "$INITD/wakeroute" ]; then
	say "stopping service"
	"$INITD/wakeroute" stop 2>/dev/null || true
	say "disabling service (removing boot symlink)"
	"$INITD/wakeroute" disable 2>/dev/null || true
fi

# --- remove init script + binary -------------------------------------------
rm -f "$INITD/wakeroute" "$SBIN/wakeroute" "$SBIN/wakeroute.bak"
say "removed binary + init script"

# --- optional purge of config + state --------------------------------------
if [ "$1" = "--purge" ]; then
	rm -rf "$ETC" "$VAR"
	say "purged $ETC and $VAR"
else
	say "config kept at $ETC (use --purge to remove)"
fi
