#define _GNU_SOURCE
#include <dlfcn.h>
/* inject_target — a stand-in for Sober's process in the injector test.
 *
 * Does the minimum a real host does (maps libc, has a thread that runs),
 * then blocks. nebula-inject is pointed at it and we verify the hook .so
 * ended up in its address space and its constructor ran.
 *
 * Built by tests/run_inject_test.sh.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Give the injector something to resolve against. */
    void *h = dlopen("libc.so.6", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed\n");
    }
    fprintf(stderr, "inject_target: pid %d ready\n", (int)getpid());
    fflush(stderr);
    for (;;) {
        sleep(1);
    }
    return 0;
}