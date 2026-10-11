// fake_vm.c — a stub "libSoberRuntime.so" for testing nebula-hook without
// Sober. Implements just enough of the Luau C API for the hook to resolve,
// and "executes" scripts by writing them to /tmp/nebula_e2e_executed.lua.
//
// Built as a shared object by tests/run_e2e_test.sh.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void LuaState;
static char pending_src[65536];
static int  loaded = 0;

// The fake VM "executes" a script by writing it to a result file — proving
// the hook really delivered it through loadstring -> pcall.
static void fake_execute(const char* src) {
    FILE* out = fopen("/tmp/nebula_e2e_executed.lua", "w");
    if (out) {
        fputs(src, out);
        fclose(out);
    }
    printf("[vm] EXECUTED SCRIPT:\n%s\n", src);
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// Exported "Luau" API — signatures must match what nebula-hook resolves.
// ---------------------------------------------------------------------------

__attribute__((noinline))
void* lua_state(void) { return (void*)0x1234; }

__attribute__((noinline))
void lua_pushcclosure(void* L, void* fn, int n) { (void)L; (void)fn; (void)n; }

__attribute__((noinline))
void lua_setfield(void* L, int idx, const char* k) { (void)L; (void)idx; (void)k; }

__attribute__((noinline))
void lua_pushstring(void* L, const char* s) { (void)L; (void)s; }

__attribute__((noinline))
int luaL_loadstring(void* L, const char* s) {
    (void)L;
    if (!s) return 1;
    strncpy(pending_src, s, sizeof(pending_src) - 1);
    loaded = 1;
    return 0;
}

__attribute__((noinline))
int lua_pcall(void* L, int nargs, int nresults, int errfunc) {
    (void)L; (void)nargs; (void)nresults; (void)errfunc;
    if (loaded) {
        loaded = 0;
        fake_execute(pending_src);
    }
    return 0;
}

__attribute__((noinline))
const char* lua_tolstring(void* L, int idx, size_t* len) {
    (void)L; (void)idx;
    if (len) *len = 0;
    return "";
}

__attribute__((noinline))
int lua_gettop(void* L) { (void)L; return 0; }

__attribute__((noinline))
int lua_type(void* L, int idx) { (void)L; (void)idx; return 0; }
