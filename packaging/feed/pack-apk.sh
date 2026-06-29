#!/bin/sh
# pack-apk.sh — build OpenWrt apk (apk-tools v3 / .apk) package(s) for a PREBUILT Velinx binary.
# RUN INSIDE an alpine container that ships apk-tools v3 (provides `apk mkpkg`). apk filenames carry
# no arch, so each token gets its OWN directory; the device selects via $(cat /etc/apk/arch) in the
# feed URL. Index generation + signing is done by the caller (feed.yml) after all tokens are packed.
#
# Usage: pack-apk.sh <binpath> <version> <release> <outdir> <arch-token> [token...]
set -eu
BIN="$1"; VER="$2"; REL="$3"; OUT="$4"; shift 4
HERE="$(cd "$(dirname "$0")" && pwd)"
INIT="$HERE/../openwrt/velinx.init"
[ -f "$BIN" ]  || { echo "pack-apk: binary not found: $BIN" >&2; exit 1; }
[ -f "$INIT" ] || { echo "pack-apk: init not found: $INIT" >&2; exit 1; }
command -v apk >/dev/null 2>&1 || { echo "pack-apk: apk-tools v3 not found (run inside alpine)" >&2; exit 1; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/usr/sbin" "$work/root/etc/init.d"
install -m0755 "$BIN"  "$work/root/usr/sbin/velinx"
install -m0755 "$INIT" "$work/root/etc/init.d/velinx"

for tok in "$@"; do
  dst="$OUT/apk/$tok"; mkdir -p "$dst"
  apk mkpkg \
    --info "name:velinx" \
    --info "version:${VER}-r${REL}" \
    --info "arch:${tok}" \
    --info "description:Velinx - VPN/proxy control panel for your router" \
    --info "url:https://github.com/awadak3davra/velinx" \
    --info "license:MIT" \
    --info "depends:firewall4 nftables wireguard-tools" \
    --files "$work/root" \
    --script "post-install:$HERE/postinst.apk" \
    -o "$dst/velinx-${VER}-r${REL}.apk"
  echo "  built apk/$tok/velinx-${VER}-r${REL}.apk"
done
