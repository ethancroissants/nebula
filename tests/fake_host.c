// fake_host.c — a stub "libSoberRuntime.so" + host app for testing nebula-hook
// without Sober. Implements just enough of the Luau C API for the hook to
// resolve, and calls lua_pcall() in a loop so the hook keeps firing.
//
// Build (see run_e2e_test.sh):
//   gcc -shared -fPIC -o libSoberRuntime.so fake_host.c
//   gcc -o host host_app.c -L. -l:libSoberRuntime.so -Wl,-rpath,'$ORIGIN'
//
// The host then "executes" queued scripts by evaluating them with a real Lua
// interpreter if available (liblua5.1), or just printing them in test mode.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Simulated Luau state: one global "script" slot the fake VM runs.
// ---------------------------------------------------------------------------

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
    printf("[host] EXECUTED SCRIPT:\n%s\n", src);
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
    // Simulate work: the fake VM runs whatever loadstring loaded.
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

// ---------------------------------------------------------------------------
// Host: loop calling pcall forever so the hook sees constant traffic.
// ---------------------------------------------------------------------------

#include <dlfcn.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    // Sanity: our own symbols must be resolvable (the hook dlsyms them).
    void* self = dlopen(0, RTLD_NOW | RTLD_GLOBAL);
    if (!self || !dlsym(self, "lua_pcall")) {
        fprintf(stderr, "[host] FATAL: symbols not globally visible; build with -rdynamic\n");
        return 1;
    }
    printf("[host] running; calling lua_pcall every 100ms (pid %d)\n", getpid());

    // NEBULA_INIT_ONLY=1: constructor-only smoke test (no pcall traffic).
    if (getenv("NEBULA_INIT_ONLY")) {
        printf("[host] init-only mode: constructor survived\n");
        return 0;
    }

    for (int i = 0; i < 600; i++) {           // ~60 s max
        lua_pcall(lua_state(), 0, 0, 0);
        // Exit early when the test says we're done.
        if (access("/tmp/nebula_e2e_done", F_OK) == 0) {
            printf("[host] done flag seen — exiting\n");
            break;
        }
        usleep(100 * 1000);
    }
    printf("[host] finished\n");
    return 0;
}
