#!/usr/bin/env python3
"""Deterministic C boundary contract: signal cancellation and missing dlsym."""
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'src'


def main():
    # Substitute probes for Rust exports. Each probe verifies the C caller's
    # state, then interrupts the simulated Rust frame with native libc I/O.
    declarations = '\n'.join((SOURCE / name).read_text()
                             for name in ('boundary.c', 'stdio.c', 'variadic.c'))
    stubs = []
    seen = set()
    for result, name, args in re.findall(r'extern (\w+) (ntcp_\w+)(\([^;]*\));', declarations):
        if name in seen:
            continue
        seen.add(name)
        classification = name.startswith('ntcp_boundary_')
        stubs.append(f'{result} {name}{args} {{ return probe({int(classification)}); }}')
    harness = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
static void *test_dlsym(void *, const char *);
#define dlsym test_dlsym
#include "boundary.c"
#include "stdio.c"
#include "variadic.c"
#undef dlsym
static void *test_dlsym(void *handle, const char *name) {
    return !strcmp(name, "epoll_pwait2") ? NULL : dlsym(handle, name);
}
static _Thread_local int probing, exercise;
static atomic_int waiting;
static int wait_epfd;
static int managed, signal_fd, cleaned, signal_count;
static void signal_io(int signo) {
    (void)signo;
    char byte;
    assert(probing);
    assert(ntcp_c_read(signal_fd, &byte, 1) == 1);
    ++signal_count;
}
static int probe(int classifier) {
    int state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    assert(state == PTHREAD_CANCEL_DISABLE);
    if (!exercise) return classifier ? managed : 17;
    if (probing) return 0; // Native fd classification inside the handler.
    probing = 1;
    assert(!pthread_cancel(pthread_self()));
    assert(!raise(SIGUSR1));
    probing = 0;
    errno = EDOM;
    return classifier ? managed : 17;
}
STUBS
static void cleanup(void *p) {
    (void)p;
    assert(!probing); // Forced unwind must occur only after the Rust return.
    ++cleaned;
}
static void *worker(void *p) {
    int op = (int)(intptr_t)p;
    exercise = 1;
    struct pollfd fd = {.fd = signal_fd, .events = POLLIN};
    fd_set set;
    FD_ZERO(&set); FD_SET(signal_fd, &set);
    struct epoll_event event;
    struct timespec zero = {0};
    pthread_cleanup_push(cleanup, NULL);
    switch (op) {
    case 0: ntcp_c_poll(&fd, 1, 0); break;
    case 1: ntcp_c_select(signal_fd + 1, &set, NULL, NULL, NULL); break;
    case 2: ntcp_c_socket(AF_UNIX, SOCK_STREAM, 0); break;
    case 3: ntcp_c_setsockopt(-1, 0, 0, NULL, 0); break;
    case 4: ntcp_c_dup(-1); break;
    case 5: ntcp_c_epoll_ctl(-1, 0, -1, NULL); break;
    case 6: ntcp_variadic_fcntl(-1, F_GETFL); break;
    case 7: ntcp_variadic_ioctl(-1, FIOCLEX); break;
    case 8: ntcp_c_fdopen(-1, "r"); break;
    case 9: assert(ntcp_c_epoll_pwait2(-1, &event, 1, &zero, NULL) == 17); break;
    }
    pthread_testcancel();
    assert(!"pending cancellation was lost");
    pthread_cleanup_pop(0);
    return NULL;
}
static void *kernel_wait(void *p) {
    (void)p;
    struct epoll_event event;
    pthread_cleanup_push(cleanup, NULL);
    atomic_store(&waiting, 1);
    ntcp_c_epoll_pwait2(wait_epfd, &event, 1, NULL, NULL);
    assert(!"blocking fallback returned");
    pthread_cleanup_pop(0);
    return NULL;
}
int main(void) {
    struct sigaction action = {.sa_handler = signal_io};
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1, &action, NULL));
    signal_fd = open("/dev/zero", O_RDONLY);
    assert(signal_fd >= 0);
    // The resolver was forced to return NULL without a production test switch.
    assert(real_epoll_pwait2 == NULL);
    for (managed = 0; managed <= 1; ++managed) {
        for (int op = 0; op <= (managed ? 9 : 8); ++op) {
            pthread_t thread;
            cleaned = 0;
            assert(!pthread_create(&thread, NULL, worker, (void *)(intptr_t)op));
            void *result;
            assert(!pthread_join(thread, &result));
            assert(result == PTHREAD_CANCELED && cleaned == 1);
        }
    }
    // Native kernel fallback: mask sizing, successful timeout, and cancellation
    // during a blocking syscall (not merely pending on entry).
    managed = 0;
    int epfd = syscall(SYS_epoll_create1, 0);
    wait_epfd = epfd;
    struct epoll_event event;
    struct timespec zero = {0};
    sigset_t mask;
    sigemptyset(&mask);
    int state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    assert(ntcp_c_epoll_pwait2(epfd, &event, 1, &zero, &mask) == 0);
    pthread_setcancelstate(state, NULL);
    assert(signal_count >= 19);
    pthread_t thread;
    cleaned = 0;
    assert(!pthread_create(&thread, NULL, kernel_wait, NULL));
    while (!atomic_load(&waiting)) sched_yield();
    usleep(20000);
    assert(!pthread_cancel(thread));
    void *result;
    assert(!pthread_join(thread, &result));
    assert(result == PTHREAD_CANCELED && cleaned == 1);
    syscall(SYS_close, epfd);
    syscall(SYS_close, signal_fd);
    puts("PASS C masks classifiers/exports against signal cancellation and missing epoll_pwait2");
}
'''.replace('STUBS', '\n'.join(stubs))
    with tempfile.TemporaryDirectory(prefix='ntcp-mask-') as directory:
        path = Path(directory)
        (path / 'mask.c').write_text(harness)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                        '-O2', '-pthread', '-fexceptions', '-I', str(SOURCE),
                        str(path / 'mask.c'), '-ldl', '-o', str(path / 'mask')], check=True)
        subprocess.run([str(path / 'mask')], check=True, timeout=20)


if __name__ == '__main__':
    main()
