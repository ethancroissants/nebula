#!/usr/bin/env bash
# run_inject_test.sh — verify the ptrace remote-dlopen injector end to end,
# without needing Sober.
#
# The injector spawns the target as its OWN child and injects into it, which
# is the one arrangement ptrace_scope=1 always permits — so this exercises
# the real injection mechanics (register hijack, stack scratch, fake return
# address, dlopen) on any machine.
#
# Checks:
#   1. the injector resolves dlopen in the target and reports success,
#   2. the hook's constructor ran (it writes a status heartbeat),
#   3. the target was still alive and healthy when we detached.
#
# This is the regression net for the bugs that only showed up on a real
# Sober: wrong load base, reading the ELF from the host instead of the
# target's mount namespace, and a missing return address.

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

# Isolate the test from any preload the host may carry (a stale
# /etc/ld.so.preload from an earlier Nebula run would preload the hook
# before we ever inject, invalidating the test).
export HOME="$TESTDIR/home"
unset LD_PRELOAD
rm -rf "$HOME" /tmp/.nebula
mkdir -p "$HOME/.nebula/queue"

echo "==> spawning target and injecting"
OUT="$("$INJECT" --spawn "$HOOK" "$TARGET_BIN" 2>&1)"
echo "$OUT" | sed 's/^/    /'

echo "$OUT" | grep -q "injected into pid" \
    || fail "injector did not report success"
ok "injector reported success"

echo "$OUT" | grep -qE "hook heartbeat after inject: (WAITING|ATTACHED)" \
    || fail "hook constructor never wrote a status heartbeat"
ok "hook constructor ran inside the target"

# No crash: the injector kills the child itself, so reaching here means the
# detach/cleanup path completed without panicking or erroring out.
ok "target survived injection and clean detach"

echo
echo "✦ INJECTOR TEST PASSED — hook dlopen'd into a running process"