// host.c — the fake host process for the e2e test. Links against the fake
// libSoberRuntime.so (which provides lua_*) and calls lua_pcall in a loop.
//
// Build (see tests/run_e2e_test.sh):
//   gcc -o host tests/host.c -L$TMP -lSoberRuntime -Wl,-rpath,$TMP
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void LuaState;

// Resolve the Luau entry points at runtime — the real Luau shared object
// exports them, exactly like the VM object inside Sober.
static LuaState* (*p_luaL_newstate)(void);
static void      (*p_lua_pcall)(LuaState*, int, int, int);

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void* rt = dlopen("libSoberRuntime.so", RTLD_NOW);
    if (!rt) {
        fprintf(stderr, "[host] FATAL: %s\n", dlerror());
        return 1;
    }
    p_luaL_newstate = (LuaState* (*)(void))dlsym(rt, "luaL_newstate");
    p_lua_pcall = (void (*)(LuaState*, int, int, int))dlsym(rt, "lua_pcall");
    if (!p_luaL_newstate || !p_lua_pcall) {
        fprintf(stderr, "[host] FATAL: lua symbols missing from libSoberRuntime.so\n");
        return 1;
    }

    // The shim's constructor already created the VM; drive pcall traffic.
    printf("[host] running; calling lua_pcall every 50ms (pid %d)\n", getpid());

    // NEBULA_INIT_ONLY=1: constructor-only smoke test (no pcall traffic).
    if (getenv("NEBULA_INIT_ONLY")) {
        printf("[host] init-only mode: constructor survived\n");
        return 0;
    }

    // The shim's game-loop thread already drives pcall traffic on the game
    // state (a Lua state must only be touched from one thread at a time), so
    // the host just waits for the test to finish.
    for (int i = 0; i < 400; i++) {           // ~20 s max
        if (access("/tmp/nebula_e2e_done", F_OK) == 0) {
            printf("[host] done flag seen — exiting\n");
            break;
        }
        usleep(50 * 1000);
    }
    printf("[host] finished\n");
    return 0;
}
