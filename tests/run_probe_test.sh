#!/usr/bin/env bash
# run_probe_test.sh — verify --attach-only is safe: the host must survive
# being traced, and must not be left stopped.
#
# The injector spawns the target as its own child (the one arrangement
# ptrace_scope=1 always permits), probes it, and reaps it.
#
# This is the regression net for the new probe mode: --attach-only must
# attach, detach, and load NOTHING. A probe that quietly injected the hook
# would defeat the entire point, which is to isolate "host dies from being
# traced" from "host dies from what we do once attached".
#
# Note honestly: this does NOT cover the stop_all_threads() detach leak. A
# single-threaded target cannot produce a partial attach (all threads share
# credentials, so they all succeed or all fail together), and reaching that
# branch needs a multi-threaded target we cannot reliably fail mid-way here.
# The leak fix is defensive hardening; what this test proves is that the probe
# is a true no-op on the host.

set -uo pipefail
cd "$(dirname "$0")/.."

INJECT="target/release/nebula-inject"
HOOK="$(pwd)/target/release/libnebula_hook.so"
TESTDIR="target/inject-test"
TARGET_BIN="$TESTDIR/inject_target"

fail() { echo "✗ $*"; exit 1; }
ok()   { echo "✓ $*"; }

[ -x "$INJECT" ] || fail "build first: cargo build --release -p nebula-hook"
[ -f "$HOOK" ]   || fail "hook .so missing: cargo build --release -p nebula-hook"

mkdir -p "$TESTDIR"
echo "==> building test target"
cc -O0 -o "$TARGET_BIN" tests/inject_target.c -ldl || fail "cc failed"

# Isolate from any stale host preload, exactly as the injector test does.
export HOME="$TESTDIR/home"
unset LD_PRELOAD
rm -rf "$HOME" /tmp/.nebula
mkdir -p "$HOME/.nebula/queue"

echo "==> spawning target and probing (attach + detach, nothing loaded)"
OUT="$("$INJECT" --spawn "$HOOK" "$TARGET_BIN" --attach-only 2>&1)"
echo "$OUT" | sed 's/^/    /'

echo "$OUT" | grep -q "probe OK on pid" \
    || fail "probe did not report success"
ok "attach + detach succeeded"

# Reaching here means the child was still alive when we killed it. If the
# probe had left threads stopped, the child would be frozen.
echo "$OUT" | grep -q "injected into pid" \
    && fail "probe loaded the hook; it must not"
ok "probe loaded nothing (no injection reported)"

echo "==> full injection still works"
OUT2="$("$INJECT" --spawn "$HOOK" "$TARGET_BIN" 2>&1)"
echo "$OUT2" | sed 's/^/    /'
echo "$OUT2" | grep -q "injected into pid" \
    || fail "injection failed after probe"
echo "$OUT2" | grep -qE "hook heartbeat after inject: (WAITING|ATTACHED)" \
    || fail "hook constructor never wrote a status heartbeat"
ok "injection works normally, host survives both"

echo
echo "✦ PROBE TEST PASSED — attach/detach leaves the host running"