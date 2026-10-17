#!/bin/sh
# Build the release archives, the container-image inputs and SHA256SUMS.
#
#   scripts/build-release.sh v1.2.3              # all platforms into ./dist
#   PLATFORMS="linux/amd64" scripts/build-release.sh dev
#
# Builds are reproducible: CGO is off, paths are trimmed, timestamps come from
# the commit, and archives are written in a fixed order with fixed ownership.
# The same commit built with the same Go toolchain gives byte-identical files.
set -eu

VERSION="${1:?usage: $0 <version>}"
PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"
PKG="github.com/TurlaFSB/logshield"

cd "$(dirname "$0")/.."
OUT="${OUT:-dist}"
COMMIT="$(git rev-parse HEAD)"
EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
DATE="$(date -u -d "@$EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X $PKG/internal/version.Version=$VERSION -X $PKG/internal/version.Commit=$COMMIT -X $PKG/internal/version.Date=$DATE"

rm -rf "$OUT"
mkdir -p "$OUT"

for platform in $PLATFORMS; do
	os="${platform%/*}"
	arch="${platform#*/}"
	ext=""
	[ "$os" = windows ] && ext=".exe"
	name="logshield_${VERSION}_${os}_${arch}"
	stage="$OUT/stage/$name"
	mkdir -p "$stage"

	echo "build: $platform"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$stage/logshield$ext" ./cmd/logshield
	cp LICENSE README.md CHANGELOG.md "$stage/"
	cp -r examples "$stage/examples"

	# Fixed mtimes, order and ownership so the archive bytes depend only on content.
	find "$stage" -exec touch -h -d "@$EPOCH" {} +
	if [ "$os" = windows ]; then
		(cd "$OUT/stage" && find "$name" -type f -print | LC_ALL=C sort | zip -X -q "../$name.zip" -@)
	else
		tar -C "$OUT/stage" --sort=name --owner=0 --group=0 --numeric-owner \
			--mtime="@$EPOCH" -cf - "$name" | gzip -n -9 >"$OUT/$name.tar.gz"
	fi

	# Raw Linux binaries are the inputs of the container image.
	if [ "$os" = linux ]; then
		mkdir -p "$OUT/image/$arch"
		cp "$stage/logshield" "$OUT/image/$arch/logshield"
	fi
done
rm -rf "$OUT/stage"

(cd "$OUT" && find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print |
	sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum >SHA256SUMS)
echo "build: wrote $(wc -l <"$OUT/SHA256SUMS") archives and SHA256SUMS to $OUT/"
