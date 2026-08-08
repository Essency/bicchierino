#!/bin/sh
# build-deb.sh <version> [arch] — stages the install tree and builds a
# .deb with dpkg-deb directly (no debian/rules ceremony, no extra
# toolchain like fpm/ruby — dpkg-deb ships with dpkg itself, always
# present on any Debian-based build host). <version> is the bare
# upstream version (no leading "v" — Debian's own convention; strip it
# from a git tag before calling this).
set -e

VERSION="${1:?usage: build-deb.sh <version-without-v-prefix> [arch]}"
ARCH="${2:-amd64}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bicchierino"
if [ ! -x "$BIN" ]; then
    echo "build-deb.sh: $BIN not found or not executable — run make first" >&2
    exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/lib/systemd/system" \
         "$STAGE/etc/bicchierino" \
         "$STAGE/usr/share/doc/bicchierino"

install -m 0755 "$BIN" "$STAGE/usr/bin/bicchierino"
install -m 0644 "$ROOT/packaging/bicchierino.service" "$STAGE/lib/systemd/system/bicchierino.service"
install -m 0640 "$ROOT/packaging/bicchierino.config" "$STAGE/etc/bicchierino/bicchierino.config"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/bicchierino/README.md"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/bicchierino/LICENSE"
install -m 0644 "$ROOT/THIRD_PARTY_LICENSES" "$STAGE/usr/share/doc/bicchierino/THIRD_PARTY_LICENSES"
install -m 0644 "$ROOT/packaging/copyright" "$STAGE/usr/share/doc/bicchierino/copyright"

install -m 0755 "$ROOT/packaging/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/packaging/prerm" "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/packaging/postrm" "$STAGE/DEBIAN/postrm"
printf '/etc/bicchierino/bicchierino.config\n' >"$STAGE/DEBIAN/conffiles"

INSTALLED_SIZE=$(du -sk "$STAGE" | cut -f1)

cat >"$STAGE/DEBIAN/control" <<EOF
Package: bicchierino
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: libssl3, libc6, systemd
Installed-Size: $INSTALLED_SIZE
Maintainer: Essency <noreply@users.noreply.github.com>
Homepage: https://github.com/Essency/bicchierino
Description: Stateless IRC-facade bridge to grappa
 bicchierino lets any real IRC client (irssi, WeeChat, HexChat, ...)
 connect to a grappa-backed account as if grappa spoke IRC natively.
 Grappa's own client-facing wire protocol is REST + Phoenix Channels
 (WebSocket), not IRC bytes; bicchierino translates between the two,
 logging into grappa on behalf of the connecting client using exactly
 the credentials that client sent.
EOF

OUT="$ROOT/bicchierino_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo "built: $OUT"
