#!/bin/bash
# Build and run libFuzzer fuzz targets for libjwt.
# Usage: ./fuzz/fuzz_clang.sh <target> [libfuzzer-args...]
#   target: jwt_verify | jwks_parse
#
# Examples:
#   ./fuzz/fuzz_clang.sh jwks_parse
#   ./fuzz/fuzz_clang.sh jwt_verify -max_total_time=300
#   ./fuzz/fuzz_clang.sh jwks_parse -jobs=4 -workers=4

set -euo pipefail

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILDDIR="${SRCDIR}/build_fuzz"

usage() {
    echo "Usage: $0 <target> [libfuzzer-args...]"
    echo ""
    echo "Targets:"
    echo "  jwt_verify   Fuzz JWT token verification (HS256)"
    echo "  jwks_parse   Fuzz JWK/JWKS JSON parsing"
    echo ""
    echo "Extra arguments are passed to libFuzzer, e.g.:"
    echo "  $0 jwks_parse -max_total_time=60"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

TARGET="$1"
shift

case "$TARGET" in
    jwt_verify)
        BINARY="fuzz_jwt_verify"
        CORPUS="${SRCDIR}/fuzz/corpus_jwt"
        ;;
    jwks_parse)
        BINARY="fuzz_jwks_parse"
        CORPUS="${SRCDIR}/fuzz/corpus_jwks"
        ;;
    *)
        echo "Error: unknown target '${TARGET}'"
        echo ""
        usage
        ;;
esac

# Fresh build
echo "=== Building fuzz targets (build_fuzz/) ==="
rm -rf "${BUILDDIR}"
CC=clang cmake -S "${SRCDIR}" -B "${BUILDDIR}" \
    -DWITH_FUZZ=ON -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug
cmake --build "${BUILDDIR}" --target "${BINARY}" -- -j"$(nproc)"

echo ""
echo "=== Running ${BINARY} with corpus ${CORPUS}/ ==="
exec "${BUILDDIR}/fuzz/${BINARY}" "${CORPUS}/" -max_len=4096 "$@"
