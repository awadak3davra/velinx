#!/bin/sh
# pack-entware.sh — build Entware/Keenetic .ipk(s): SAME binary, but the /opt layout, the S99velinx
# init, Entware arch tokens, and minimal deps (Entware routing is NDM-native, not nftables, so the
# package carries no firewall deps).
#
# Usage: pack-entware.sh <binpath> <version> <release> <outdir> <entware-token> [token...]
set -eu
BIN="$1"; VER="$2"; REL="$3"; OUT="$4"; shift 4
HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="$HERE/../S99velinx"
: "${SOURCE_DATE_EPOCH:=0}"
[ -f "$BIN" ]  || { echo "pack-entware: binary not found: $BIN" >&2; exit 1; }
[ -f "$INIT" ] || { echo "pack-entware: init not found: $INIT" >&2; exit 1; }
mkdir -p "$OUT"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

mkdir -p "$work/data/opt/sbin" "$work/data/opt/etc/init.d"
install -m0755 "$BIN"  "$work/data/opt/sbin/velinx"
install -m0755 "$INIT" "$work/data/opt/etc/init.d/S99velinx"
isize="$(du -sb "$work/data" | cut -f1)"

tar_repro() {
  tar --numeric-owner --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH}" --sort=name -C "$1" -czf "$2" .
}
tar_repro "$work/data" "$work/data.tar.gz"

mkdir -p "$work/control"
printf '2.0\n' > "$work/debian-binary"
for tok in "$@"; do
  cat > "$work/control/control" <<EOF
Package: velinx
Version: ${VER}-${REL}
Architecture: ${tok}
Maintainer: Velinx <noreply@velinx.dev>
Section: net
Priority: optional
Installed-Size: ${isize}
Description: Self-hosted web panel to configure any VPN/proxy protocol on your router
 (Entware/Keenetic build, installs under /opt). One static Go binary embedding the UI.
EOF
  tar_repro "$work/control" "$work/control.tar.gz"
  out_dir="$OUT/$tok"; mkdir -p "$out_dir"
  out="$out_dir/velinx_${VER}-${REL}_${tok}.ipk"
  rm -f "$out"
  ( cd "$work" && ar rc "$out" debian-binary control.tar.gz data.tar.gz )
  echo "  built $tok/$(basename "$out")"
done
