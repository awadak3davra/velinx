#!/bin/sh
# pack-ipk.sh — build OpenWrt .ipk package(s) for a PREBUILT Velinx binary, by hand (no SDK).
# An .ipk is just an ar archive of: debian-binary, control.tar.gz, data.tar.gz (in that order).
# One data payload is built once; only the control's Architecture field differs per token, so one
# binary yields one .ipk per CPU-family token.
#
# Usage: pack-ipk.sh <binpath> <version> <release> <outdir> <arch-token> [arch-token...]
set -eu
BIN="$1"; VER="$2"; REL="$3"; OUT="$4"; shift 4
HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="$HERE/../openwrt/velinx.init"
: "${SOURCE_DATE_EPOCH:=0}"
[ -f "$BIN" ]  || { echo "pack-ipk: binary not found: $BIN" >&2; exit 1; }
[ -f "$INIT" ] || { echo "pack-ipk: init not found: $INIT" >&2; exit 1; }
mkdir -p "$OUT"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# data tree: the binary + the procd init, reproducible (fixed owner/mtime, sorted).
mkdir -p "$work/data/usr/sbin" "$work/data/etc/init.d"
install -m0755 "$BIN"  "$work/data/usr/sbin/velinx"
install -m0755 "$INIT" "$work/data/etc/init.d/velinx"
# Keep the saved config/connections across a firmware sysupgrade (the binary is wiped from the
# overlay and reinstalled from the feed; /etc/velinx must survive). OpenWrt reads /lib/upgrade/keep.d.
if [ -f "$HERE/../openwrt/velinx.keep" ]; then
  mkdir -p "$work/data/lib/upgrade/keep.d"
  install -m0644 "$HERE/../openwrt/velinx.keep" "$work/data/lib/upgrade/keep.d/velinx"
fi
isize="$(du -sb "$work/data" | cut -f1)"

tar_repro() {
  tar --numeric-owner --owner=0 --group=0 --mtime="@${SOURCE_DATE_EPOCH}" --sort=name -C "$1" -czf "$2" .
}
tar_repro "$work/data" "$work/data.tar.gz"

mkdir -p "$work/control"
install -m0755 "$HERE/postinst" "$work/control/postinst"
install -m0755 "$HERE/prerm"    "$work/control/prerm"
printf '2.0\n' > "$work/debian-binary"

for tok in "$@"; do
  sed -e "s/@VER@/$VER/g" -e "s/@REL@/$REL/g" -e "s/@ARCH@/$tok/g" -e "s/@ISIZE@/$isize/g" \
      "$HERE/control.tmpl" > "$work/control/control"
  tar_repro "$work/control" "$work/control.tar.gz"
  out_dir="$OUT/$tok"; mkdir -p "$out_dir"
  out="$out_dir/velinx_${VER}-${REL}_${tok}.ipk"
  rm -f "$out"
  ( cd "$work" && ar rc "$out" debian-binary control.tar.gz data.tar.gz )
  echo "  built $tok/$(basename "$out")"
done
