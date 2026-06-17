#!/bin/sh
# Remove WakeRoute (wakeroute). Keeps your config by default.
#   ./uninstall.sh           # remove binary + service, keep /opt/etc/wakeroute
#   ./uninstall.sh --purge   # also remove config + runtime state
set -e
INITD=/opt/etc/init.d
say() { echo "[wakeroute] $*"; }

if [ -x "$INITD/S99wakeroute" ]; then
  say "stopping service"
  "$INITD/S99wakeroute" stop 2>/dev/null || true
fi
rm -f "$INITD/S99wakeroute" /opt/sbin/wakeroute /opt/sbin/wakeroute.bak
say "removed binary + init script"

if [ "$1" = "--purge" ]; then
  rm -rf /opt/etc/wakeroute /opt/var/wakeroute
  say "purged /opt/etc/wakeroute and /opt/var/wakeroute"
else
  say "config kept at /opt/etc/wakeroute (use --purge to remove)"
fi
