#!/usr/bin/env bash
# run_e2e_test.sh — end-to-end test of the hook pipeline against the REAL
# Luau VM (compiled from luau-lang/luau), without needing Sober/Roblox.
#
# Builds:
#   1. the real Luau VM + Compiler as a shared object named libSoberRuntime.so
#      (mimicking Sober's process layout — the hook can't tell the difference),
#   2. a host that runs a game-style loop calling lua_pcall,
#   3. libnebula_hook.so, preloaded into the host.
#
# Then it queues a script and verifies it is compiled by luau_compile, loaded
# by luau_load, executed by lua_pcall inside the REAL Luau VM — with print()
# output captured from inside the VM.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; rm -f /tmp/nebula_e2e_done /tmp/nebula_e2e_out.log' EXIT

LUAU_DIR="${LUAU_DIR:-/tmp/opencode/luau}"
BUILD_DIR="/tmp/opencode/luau_build"

echo "==> building real Luau VM as libSoberRuntime.so…"
if [ ! -d "$LUAU_DIR" ]; then
    git clone --depth 1 https://github.com/luau-lang/luau "$LUAU_DIR"
fi
mkdir -p "$BUILD_DIR"
if [ ! -f "$BUILD_DIR/.built" ]; then
    LU="$LUAU_DIR"
    SRCS=$(ls $LU/Common/src/*.cpp $LU/Ast/src/*.cpp $LU/Compiler/src/*.cpp \
              $LU/Bytecode/src/*.cpp $LU/Config/src/*.cpp $LU/VM/src/*.cpp \
           | grep -v "main\|tests\|UnitTest")
    cd "$BUILD_DIR"
    for f in $SRCS; do
        g++ -std=c++17 -O2 -fPIC \
            '-DLUA_API=extern "C"' '-DLUALIB_API=extern "C"' '-DLUACODE_API=extern "C"' \
            -DLUA_USE_LONGJMP=1 \
            -I$LU/Common/include -I$LU/Ast/include -I$LU/Compiler/include \
            -I$LU/Bytecode/include -I$LU/Config/include -I$LU/VM/include \
            -c "$f" -o "$(basename "$f").o" &
        while [ "$(jobs -r | wc -l)" -ge 8 ]; do wait -n; done
    done
    wait
    touch .built
fi
cd "$REPO"

g++ -std=c++17 -O1 -fPIC -shared \
    '-DLUA_API=extern "C"' '-DLUALIB_API=extern "C"' '-DLUACODE_API=extern "C"' \
    -DLUA_USE_LONGJMP=1 \
    -I"$LUAU_DIR/VM/include" -I"$LUAU_DIR/Compiler/include" \
    -o "$TMP/libSoberRuntime.so" \
    tests/luau_shim.c "$BUILD_DIR"/*.o \
    -lpthread

echo "==> building host (links the real Luau VM)…"
gcc -std=c11 -O1 -o "$TMP/host" tests/host.c -L"$TMP" -lSoberRuntime -Wl,-rpath,"$TMP"

echo "==> building hook (debug for faster link)…"
cargo build -p nebula-hook >/dev/null 2>&1
HOOK="$PWD/target/debug/libnebula_hook.so"

echo "==> queueing test script…"
mkdir -p "$TMP/.nebula/queue"
cat > "$TMP/.nebula/queue/exec.lua" <<'LUA'
-- exercises the REAL Luau VM end to end
local sum = 0
for i = 1, 100 do sum += i end
print("nebula e2e: sum(1..100) =", sum)
nebula_log("e2e bridge alive; ping=" .. nebula_ping())
print("executor status: " .. nebula_status())
LUA

echo "==> launching host with hook preloaded (real Luau inside)…"
HOME="$TMP" LD_PRELOAD="$HOOK" "$TMP/host" > /tmp/nebula_e2e_out.log 2>&1 &
HOST_PID=$!

echo "==> waiting for execution (up to 20 s)…"
OK=0
for _ in $(seq 1 100); do
    if grep -q "nebula e2e: sum" /tmp/nebula_e2e_out.log 2>/dev/null; then
        OK=1
        break
    fi
    if ! kill -0 "$HOST_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

touch /tmp/nebula_e2e_done
wait "$HOST_PID" 2>/dev/null || true

echo "---- VM output (from inside real Luau):"
cat /tmp/nebula_e2e_out.log
echo "---- hook log:"
cat "$TMP/.nebula/queue/log" || true
echo "----"

if [ "$OK" = 1 ]; then
    echo "✦ E2E TEST PASSED — script executed inside the real Luau VM"
else
    echo "✗ E2E TEST FAILED — script output never appeared" >&2
    exit 1
fi
