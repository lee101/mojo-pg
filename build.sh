#!/usr/bin/env bash
# usage: ./build.sh [src.mojo] [out]   env: MOJO (compiler path), MOJO_BUILD_LOCK, BUILD_TIMEOUT
set -euo pipefail
cd "$(dirname "$0")"
if [ -n "${MOJO:-}" ]; then M=("$MOJO")
elif command -v pixi >/dev/null; then M=(pixi run --frozen mojo)
else M=(mojo); fi
SRC=${1:-tests/test_pg.mojo}
OUT=${2:-build/$(basename "$SRC" .mojo)}
mkdir -p build
tmp=$(mktemp build/.b.XXXXXX)
trap 'rm -f "$tmp"' EXIT
flock "${MOJO_BUILD_LOCK:-${TMPDIR:-/tmp}/mojo-build.lock}" timeout "${BUILD_TIMEOUT:-1200}" nice "${M[@]}" build --fp-mode contract=off -O3 -I src -I vendor/mojo-parity/src "$SRC" -o "$tmp" -Xlinker -lssl -Xlinker -lcrypto
chmod +x "$tmp"
mv -f "$tmp" "$OUT"
trap - EXIT
echo "built $OUT"
