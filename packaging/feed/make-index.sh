#!/bin/sh
# make-index.sh — (re)generate + usign-sign the opkg `Packages` index for every per-token dir under
# the feed root (both the OpenWrt ipk/ tree and the Entware entware/ tree). Pure sh + ar/tar/gzip/
# sha256sum + the bundled usigntool — no perl/opkg-utils needed. The WHOLE index is rebuilt from the
# current package set every run (single-signed-index trust model; never append).
#
# Usage: make-index.sh <feed-root> <usign-sec> <usigntool-bin>
#   apk indexes (packages.adb) are produced+signed separately inside the apk container (feed.yml).
set -eu
ROOT="$1"; USEC="$2"; UTOOL="$3"

for d in "$ROOT"/ipk/*/ "$ROOT"/entware/*/; do
  [ -d "$d" ] || continue
  pkgs="${d%/}/Packages"
  : > "$pkgs"
  found=0
  for ipk in "${d%/}"/*.ipk; do
    [ -e "$ipk" ] || continue
    found=1
    tmp="$(mktemp -d)"
    ar p "$ipk" control.tar.gz | tar -xz -C "$tmp"
    ctl="$(find "$tmp" -name control -type f | head -n1)"
    sz="$(wc -c < "$ipk" | tr -d ' ')"
    sha="$(sha256sum "$ipk" | cut -d' ' -f1)"
    cat "$ctl" >> "$pkgs"
    printf 'Filename: %s\nSize: %s\nSHA256sum: %s\n\n' "$(basename "$ipk")" "$sz" "$sha" >> "$pkgs"
    rm -rf "$tmp"
  done
  if [ "$found" != 1 ]; then rm -f "$pkgs"; continue; fi
  gzip -9kf "$pkgs"
  "$UTOOL" sign -sec "$USEC" -m "$pkgs" -out "${d%/}/Packages.sig"
  echo "  indexed + signed ${d%/}/Packages ($(grep -c '^Package:' "$pkgs") pkgs)"
done
