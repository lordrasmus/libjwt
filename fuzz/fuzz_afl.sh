#!/bin/bash
# Build and run AFL++ fuzz targets for libjwt.
# Downloads and builds AFL++ automatically if not found.
#
# Usage: ./fuzz/fuzz_afl.sh [-j N] <target> [afl-fuzz-args...]
#   target: jwt_verify | jwks_parse
#
# Examples:
#   ./fuzz/fuzz_afl.sh jwks_parse
#   ./fuzz/fuzz_afl.sh -j 4 jwt_verify
#   ./fuzz/fuzz_afl.sh -j 8 jwks_parse -P exploit

set -euo pipefail

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILDDIR="${SRCDIR}/build_afl"
AFLDIR="${SRCDIR}/fuzz/AFLplusplus"
AFL_REPO="https://github.com/AFLplusplus/AFLplusplus.git"
JOBS=1

usage() {
    echo "Usage: $0 [-j N] <target> [afl-fuzz-args...]"
    echo ""
    echo "Options:"
    echo "  -j N   Run N parallel fuzzer instances (1 main + N-1 secondary)"
    echo ""
    echo "Targets:"
    echo "  jwt_verify   Fuzz JWT token verification (HS256)"
    echo "  jwks_parse   Fuzz JWK/JWKS JSON parsing"
    echo ""
    echo "Extra arguments are passed to afl-fuzz, e.g.:"
    echo "  $0 -j 4 jwks_parse -t 5000"
    exit 1
}

# Parse our options before the target
while getopts ":j:" opt; do
    case "$opt" in
        j) JOBS="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

if [ $# -lt 1 ]; then
    usage
fi

TARGET="$1"
shift

case "$TARGET" in
    jwt_verify)
        BINARY="afl_jwt_verify"
        CORPUS="${SRCDIR}/fuzz/corpus_jwt"
        ;;
    jwks_parse)
        BINARY="afl_jwks_parse"
        CORPUS="${SRCDIR}/fuzz/corpus_jwks"
        ;;
    *)
        echo "Error: unknown target '${TARGET}'"
        echo ""
        usage
        ;;
esac

# ---------------------------------------------------------------------------
# Locate or build AFL++
# ---------------------------------------------------------------------------
ensure_aflpp() {
    # Prefer system-installed or user-supplied paths
    AFL_CC="${AFL_CC:-$(command -v afl-clang-fast 2>/dev/null || true)}"
    AFL_FUZZ="${AFL_FUZZ:-$(command -v afl-fuzz 2>/dev/null || true)}"

    # Check for a previous local build
    if [ -z "${AFL_CC}" ] && [ -x "${AFLDIR}/afl-clang-fast" ]; then
        AFL_CC="${AFLDIR}/afl-clang-fast"
    fi
    if [ -z "${AFL_FUZZ}" ] && [ -x "${AFLDIR}/afl-fuzz" ]; then
        AFL_FUZZ="${AFLDIR}/afl-fuzz"
    fi

    # Both found — nothing to do
    if [ -n "${AFL_CC}" ] && [ -n "${AFL_FUZZ}" ]; then
        return
    fi

    echo "=== AFL++ not found, building from source into fuzz/AFLplusplus/ ==="

    # Check build dependencies
    for cmd in git make clang llvm-config; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "Error: '${cmd}' is required to build AFL++."
            exit 1
        fi
    done

    if [ ! -d "${AFLDIR}" ]; then
        git clone --depth 1 "${AFL_REPO}" "${AFLDIR}"
    else
        echo "  (source tree exists, rebuilding)"
    fi

    make -C "${AFLDIR}" -j"$(nproc)" source-only

    AFL_CC="${AFLDIR}/afl-clang-fast"
    AFL_FUZZ="${AFLDIR}/afl-fuzz"

    if [ ! -x "${AFL_CC}" ] || [ ! -x "${AFL_FUZZ}" ]; then
        echo "Error: AFL++ build failed."
        exit 1
    fi

    echo "=== AFL++ ready ==="
    echo ""
}

ensure_aflpp

OUTDIR="${SRCDIR}/fuzz/findings_${TARGET}"

# Fresh build
echo "=== Building AFL++ targets (build_afl/) ==="
rm -rf "${BUILDDIR}"
CC="${AFL_CC}" cmake -S "${SRCDIR}" -B "${BUILDDIR}" \
    -DWITH_AFL=ON -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug
cmake --build "${BUILDDIR}" --target "${BINARY}" -- -j"$(nproc)"

echo ""
echo "=== Running afl-fuzz (${JOBS} instance(s)) ==="
echo "  binary:  ${BUILDDIR}/fuzz/${BINARY}"
echo "  corpus:  ${CORPUS}/"
echo "  output:  ${OUTDIR}/"
echo ""

PIDS=()

cleanup() {
    echo ""
    echo "=== Stopping all AFL++ instances ==="
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
}
trap cleanup INT TERM

# Launch secondary instances in background
for ((i = 2; i <= JOBS; i++)); do
    id=$(printf "s%02d" "$i")
    "${AFL_FUZZ}" \
        -S "$id" \
        -i "${CORPUS}" \
        -o "${OUTDIR}" \
        "$@" \
        -- "${BUILDDIR}/fuzz/${BINARY}" >/dev/null 2>&1 &
    PIDS+=($!)
    echo "  started secondary ${id} (pid $!)"
done

# Main instance in foreground (shows the UI)
exec "${AFL_FUZZ}" \
    -M main \
    -i "${CORPUS}" \
    -o "${OUTDIR}" \
    "$@" \
    -- "${BUILDDIR}/fuzz/${BINARY}"
