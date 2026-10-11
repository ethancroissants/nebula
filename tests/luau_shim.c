// shim.c — turns the real Luau static libraries into a shared object that
// mimics the Luau host inside Sober: it exposes lua_* C symbols and hosts a
// long-lived VM that behaves like the game (calls lua_pcall in a loop from
// the main thread, opening a window for the hook to run queued scripts).
//
// Built by tests/run_e2e_test.sh against the real luau-lang/luau sources.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

// ---------------------------------------------------------------------------
// The "game" VM: created lazily by the shim's constructor.
// ---------------------------------------------------------------------------

static lua_State* G_L = NULL;
static volatile int G_running = 1;

static void* game_loop(void* arg) {
    (void)arg;

    // Create the VM here, after every static initializer has run.
    G_L = luaL_newstate();
    if (!G_L) {
        fprintf(stderr, "[vm] failed to create Lua state\n");
        return NULL;
    }
    luaL_openlibs(G_L);
    // Globals stay writable so the hook can register its bridge functions;
    // Roblox's own state also keeps a writable global environment.

    printf("[vm] game loop running; calling lua_pcall every 50ms\n");
    while (G_running) {
        // Load a fresh chunk and call it, exactly like a game scheduling a
        // script: keeps the stack balanced and the hook's pcall firing.
        size_t bc_size = 0;
        char* bc = luau_compile("return 1", 8, NULL, &bc_size);
        if (bc && bc_size > 0) {
            if (luau_load(G_L, "=warmup", bc, bc_size, 0) == 0)
                lua_pcall(G_L, 0, 0, 0);
            free(bc);
        }
        if (access("/tmp/nebula_e2e_done", F_OK) == 0) break;
        usleep(50 * 1000);
    }
    printf("[vm] game loop finished\n");
    return NULL;
}

__attribute__((constructor))
static void vm_start(void) {
    // The state is created on the game-loop thread, NOT in this constructor:
    // C++ static initializers (Luau's size-class tables) may run after
    // constructors linked earlier, and state creation needs them ready.
    pthread_t t;
    pthread_create(&t, NULL, game_loop, NULL);
    pthread_detach(t);
}

__attribute__((destructor))
static void vm_stop(void) {
    G_running = 0;
    if (G_L) lua_close(G_L);
    G_L = NULL;
}

/// Exported: nonzero once the game VM is ready for pcall traffic.
__attribute__((visibility("default")))
int nebula_vm_ready(void) {
    return G_L != NULL;
}
