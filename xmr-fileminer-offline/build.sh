#!/usr/bin/env bash
# build.sh -- build librandomx.so and the native mining engine.
#
#   ./build.sh              build (clones RandomX if needed, runs a light self-test)
#   ./build.sh --full-test  also run the 2 GB full-dataset self-test (needs ~2.7 GB RAM)
#   ./build.sh --force      rebuild RandomX even if lib/librandomx.so exists
#   ./build.sh --quiet      less chatter
#
# Requirements: gcc (or clang), make, git, python3. cmake is auto-installed with
# pip if it is missing.
set -euo pipefail
cd "$(dirname "$0")"

JOBS="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 4)"
FULL_TEST=0
FORCE=0
QUIET=0
for arg in "$@"; do
    case "$arg" in
        --full-test) FULL_TEST=1 ;;
        --force) FORCE=1 ;;
        --quiet) QUIET=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done
say() { [ "$QUIET" = 1 ] || echo "$@"; }

mkdir -p lib bin third_party

# ---------------------------------------------------------------- cmake ----
if ! command -v cmake >/dev/null 2>&1; then
    if [ -x /usr/local/bin/cmake ]; then
        PATH="$PATH:/usr/local/bin"
    else
        say "cmake not found -- installing it with pip (user-level)..."
        python3 -m pip install --quiet --user cmake || {
            echo "ERROR: cannot install cmake. Install it manually (apt install cmake)." >&2
            exit 1
        }
        PATH="$PATH:$(python3 -m site --user-base)/bin"
    fi
fi

# --------------------------------------------------------------- randomx ----
RANDOMX_DIR=third_party/RandomX
if [ ! -d "$RANDOMX_DIR/src" ]; then
    say "cloning RandomX (upstream, tevador/RandomX)..."
    git clone --depth 1 --quiet https://github.com/tevador/RandomX.git "$RANDOMX_DIR"
fi

if [ "$FORCE" = 1 ] || [ ! -f lib/librandomx.so ]; then
    say "building librandomx.so (Release, runtime CPU detection)..."
    cmake -S "$RANDOMX_DIR" -B "$RANDOMX_DIR/build" \
        -DCMAKE_BUILD_TYPE=Release -DARCH=default -DBUILD_SHARED_LIBS=ON >/dev/null
    cmake --build "$RANDOMX_DIR/build" -j "$JOBS" --target randomx >/dev/null
    cp "$RANDOMX_DIR/build/librandomx.so" lib/
    git -C "$RANDOMX_DIR" log -1 --format='RandomX commit %H (%ad)' --date=short \
        > lib/VERSION.txt 2>/dev/null || true
else
    say "lib/librandomx.so already present (use --force to rebuild)"
fi

# ------------------------------------------------------------- our tools ----
CC="${CC:-gcc}"
INCLUDES=(-I"$RANDOMX_DIR/src")
LINKS=(-Llib -lrandomx -Wl,-rpath,'$ORIGIN/../lib' -lm -pthread)

say "building bin/miner_native and bin/rx_test..."
"$CC" -O2 -Wall -Wextra "${INCLUDES[@]}" -o bin/miner_native miner_native.c "${LINKS[@]}"
"$CC" -O2 -Wall -Wextra "${INCLUDES[@]}" -o bin/rx_test rx_test.c "${LINKS[@]}"

# --------------------------------------------------------------- selftest ---
say ""
say "running RandomX self-test (official test vector)..."
./bin/rx_test light >/dev/null
say "  light mode: PASS"
if [ "$FULL_TEST" = 1 ]; then
    ./bin/rx_test full
    say "  full  mode: PASS"
fi

say ""
say "build OK:"
say "  lib/librandomx.so   (hash library)"
say "  bin/miner_native    (native engine)"
say "  bin/rx_test         (self-test tool)"
say ""
say "For maximum hashrate reserve 2 MB huge pages once (needs ~2.6 GB free):"
say "    echo 1300 | sudo tee /proc/sys/vm/nr_hugepages"
say "    # persistent:  echo 'vm.nr_hugepages = 1300' | sudo tee /etc/sysctl.d/99-xmr.conf"
say "    # 1040 pages = 2 GB dataset, 128 = 256 MB cache, +1 per mining thread"
say "If that fails, run: sync && echo 3 | sudo tee /proc/sys/vm/drop_caches  (then retry)"
say "Check what you got:  grep -i huge /proc/meminfo"
