#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>

#define FAULT(expr) do { errno = 0; assert((expr) == -1); assert(errno == EFAULT); } while (0)
static void *bad = (void *)4096;
/* Runtime lengths and visible local object sizes really emit the fortify ABI. */
__attribute__((noinline)) static ssize_t checked_recv(int fd, size_t n) {
    char bytes[8];
    return recv(fd, bytes, n, MSG_DONTWAIT);
}
__attribute__((noinline)) static ssize_t checked_recvfrom(int fd, size_t n) {
    char bytes[8];
    return recvfrom(fd, bytes, n, MSG_DONTWAIT, NULL, NULL);
}
__attribute__((noinline)) static int checked_poll(int fd, nfds_t n) {
    struct pollfd p[1] = {{fd, POLLIN, 0}};
    return poll(p, n, 0);
}
__attribute__((noinline)) static int checked_ppoll(int fd, nfds_t n) {
    struct pollfd p[1] = {{fd, POLLIN, 0}};
    struct timespec t = {0};
    return ppoll(p, n, &t, NULL);
}
__attribute__((noinline)) static ssize_t checked_read(int fd, size_t n) {
    char bytes[8];
    return read(fd, bytes, n);
}
static void fortify(int fd) {
    volatile size_t valid = 0;
    assert(checked_recv(fd, valid) == 0);
    assert(checked_recvfrom(fd, valid) == 0);
    assert(checked_read(fd, valid) == 0);
    valid = 1;
    assert(checked_poll(fd, valid) >= 0);
    assert(checked_ppoll(fd, valid) >= 0);
    for (int i = 0; i < 5; ++i) {
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) {
            volatile size_t too_big = 9;
            switch (i) {
            case 0: (void)checked_recv(fd, too_big); break;
            case 1: (void)checked_recvfrom(fd, too_big); break;
            case 2: (void)checked_poll(fd, too_big); break;
            case 3: (void)checked_ppoll(fd, too_big); break;
            default: (void)checked_read(fd, too_big); break;
            }
            _exit(99);
        }
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
}
static void native(void) {
    int pipes[2];
    assert(pipe(pipes) == 0);
    for (int i = 0; i < 2; ++i) {
        int owner = i ? -getpgrp() : getpid();
        assert(fcntl(pipes[0], F_SETOWN, owner) == 0);
        errno = ECHILD;
        assert(fcntl(pipes[0], F_GETOWN) == owner);
        assert(errno == ECHILD);
        errno = ECHILD;
        assert(fcntl64(pipes[0], F_GETOWN) == owner);
        assert(errno == ECHILD);
    }
    FAULT(select(1, bad, NULL, NULL, NULL));
    FAULT(poll(bad, 1, 0));
    struct timespec zero = {0};
    FAULT(ppoll(bad, 1, &zero, NULL));
    FAULT(pselect(1, bad, NULL, NULL, &zero, NULL));
    FAULT(write(pipes[1], bad, 1));
    FAULT(writev(pipes[1], bad, 1));
    assert(write(pipes[1], "x", 1) == 1);
    FAULT(read(pipes[0], bad, 1));
    struct pollfd *large = calloc(4097, sizeof(*large));
    assert(large);
    for (size_t i = 0; i < 4097; ++i) large[i].fd = -1;
    assert(poll(large, 4097, 0) == 0);
    assert(ppoll(large, 4097, &zero, NULL) == 0);
    free(large);
    void *large_set = calloc(1, 256);
    assert(large_set);
    struct timeval tv = {0};
    assert(select(2048, large_set, NULL, NULL, &tv) == 0);
    assert(pselect(2048, large_set, NULL, NULL, &zero, NULL) == 0);
    free(large_set);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    assert(ep >= 0);
    errno = 0;
    assert(epoll_wait(ep, bad, 0, 0) == -1 && errno == EINVAL);
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(write(pair[1], "x", 1) == 1);
    fortify(pair[0]);
    close(pair[0]); close(pair[1]); close(ep); close(pipes[0]); close(pipes[1]);
}
static int descriptors(void) {
    DIR *dir = opendir("/proc/self/fd");
    assert(dir);
    int n = 0;
    while (readdir(dir)) ++n;
    assert(closedir(dir) == 0);
    return n;
}
static void virtual_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    FAULT(bind(fd, bad, sizeof(struct sockaddr_in)));
    FAULT(connect(fd, bad, sizeof(struct sockaddr_in)));
    socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr = {0};
    FAULT(getsockname(fd, bad, &len));
    FAULT(getsockname(fd, (void *)&addr, bad));
    FAULT(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, bad, 4));
    FAULT(ioctl(fd, FIONBIO, bad));
    FAULT(ioctl(fd, FIONREAD, bad));
    FAULT(write(fd, bad, 1));
    FAULT(writev(fd, bad, 1));
    FAULT(readv(fd, bad, 1));
    FAULT(sendmsg(fd, bad, 0));
    FAULT(recvmsg(fd, bad, 0));
    FAULT(poll(bad, 1, 0));
    FAULT(select(fd + 1, bad, NULL, NULL, NULL));
    FAULT(pselect(fd + 1, bad, NULL, NULL, NULL, NULL));
    int ep = epoll_create1(0);
    assert(ep >= 0);
    FAULT(epoll_ctl(ep, EPOLL_CTL_ADD, fd, bad));
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char *mem = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mem != MAP_FAILED);
    assert(mprotect(mem + page, page, PROT_NONE) == 0);
    FAULT(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, mem + page - 2, 4));
    int one = 1;
    memcpy(mem + 1, &one, 4);
    assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, mem + 1, 4) == 0);
    len = 4;
    assert(getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, mem + 1, &len) == 0);
    assert(!memcmp(mem + 1, &one, 4));
    errno = 0;
    volatile size_t malicious = SIZE_MAX;
    assert(write(fd, mem, malicious) == -1 && errno == EINVAL);
    struct iovec huge[2] = {{mem, SIZE_MAX}, {mem, 1}};
    errno = 0;
    assert(writev(fd, huge, 2) == -1 && errno == EINVAL);
    struct pollfd pf = {fd, POLLIN, 0};
    memcpy(mem, &pf, sizeof(pf));
    assert(mprotect(mem, page, PROT_READ) == 0);
    len = 4;
    FAULT(getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, mem, &len));
    FAULT(ioctl(fd, FIONREAD, mem));
    FAULT(poll((void *)mem, 1, 0));
    assert(mprotect(mem, page, PROT_READ | PROT_WRITE) == 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(16380);
    assert(inet_pton(AF_INET, "10.73.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (void *)&addr, sizeof(addr)) == 0);
    struct pollfd ready = {fd, POLLIN, 0};
    assert(poll(&ready, 1, 5000) == 1);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 123};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0);
    FAULT(epoll_wait(ep, bad, 1, 0));
    volatile size_t valid = 0;
    assert(checked_recv(fd, valid) == 0);
    assert(checked_recvfrom(fd, valid) == 0);
    assert(checked_read(fd, valid) == 0);
    valid = 1;
    assert(checked_poll(fd, valid) == 1);
    errno = 0;
    assert(checked_ppoll(fd, valid) == -1 && errno == EOPNOTSUPP);
    FAULT(recv(fd, bad, 6, 0));
    int available = 0;
    assert(ioctl(fd, FIONREAD, &available) == 0 && available >= 6);
    FAULT(read(fd, mem + page - 2, 6));
    assert(mprotect(mem, page, PROT_READ) == 0);
    FAULT(recv(fd, mem, 6, 0));
    struct iovec v[2] = {{&available, 2}, {bad, 4}};
    FAULT(readv(fd, v, 2));
    struct msghdr msg = {.msg_iov = v, .msg_iovlen = 2};
    FAULT(recvmsg(fd, &msg, 0));
    char bytes[8] = {0};
    assert(mprotect(mem, page, PROT_READ | PROT_WRITE) == 0);
    struct iovec good = {bytes, 6};
    struct msghdr readonly_header = {.msg_iov = &good, .msg_iovlen = 1};
    memcpy(mem, &readonly_header, sizeof(readonly_header));
    assert(mprotect(mem, page, PROT_READ) == 0);
    FAULT(recvmsg(fd, (void *)mem, 0));
    assert(!memcmp(bytes, "abcdef", 6)); /* Partial copyout is allowed; stream isn't consumed. */
    FAULT(recvfrom(fd, bytes, 6, 0, bad, &len));
    assert(read(fd, bytes, 6) == 6 && !memcmp(bytes, "abcdef", 6));
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    addr.sin_port = htons(16381);
    assert(inet_pton(AF_INET, "10.73.0.2", &addr.sin_addr) == 1);
    assert(bind(listener, (void *)&addr, sizeof(addr)) == 0);
    assert(listen(listener, 8) == 0);
    int before = descriptors();
    len = sizeof(addr);
    FAULT(accept4(listener, bad, &len, 0));
    assert(descriptors() == before);
    assert(close(listener) == 0);
    native(); /* Wholly native calls while the virtual runtime is initialized. */
    munmap(mem, page * 2);
    close(ep);
    assert(close(fd) == 0);
}
int main(int argc, char **argv) {
    (void)argv;
    struct rlimit core = {0};
    assert(setrlimit(RLIMIT_CORE, &core) == 0);
    alarm(15);
    if (argc > 1) virtual_socket(); else native();
    puts("ABI safety: PASS");
    return 0;
}
