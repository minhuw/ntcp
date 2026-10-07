#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static int connected(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(16382),
                              .sin_addr.s_addr = htonl(0x0a490001)};
    assert(connect(fd, (void *)&addr, sizeof(addr)) == 0);
    return fd;
}
static void exchange(int fd) {
    char c = 'x', out = 0;
    assert(write(fd, &c, 1) == 1);
    assert(read(fd, &out, 1) == 1 && out == c);
}
static void control(int ep, int op, int fd, uint32_t flags, uint64_t data) {
    struct epoll_event event = {.events = flags, .data.u64 = data};
    assert(epoll_ctl(ep, op, fd, &event) == 0);
}
static void events(int ep, unsigned bits, int count) {
    struct epoll_event out[8];
    int n = epoll_wait(ep, out, 8, 1000);
    assert(n == count);
    unsigned seen = 0;
    for (int i = 0; i < n; ++i) {
        assert(out[i].events & EPOLLOUT);
        seen |= 1u << out[i].data.u64;
    }
    assert(seen == bits);
}
int main(int argc, char **argv) {
    int managed = argc == 2 && strcmp(argv[1], "--virtual") == 0;
    int fd = connected(), alias = dup(fd);
    assert(alias >= 0 && alias != fd);
    assert(fcntl(fd, F_GETFD) == FD_CLOEXEC && fcntl(alias, F_GETFD) == 0);
    assert(fcntl(alias, F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
    assert(fcntl(fd, F_SETFL, 0) == 0);
    assert(!(fcntl(alias, F_GETFL) & O_NONBLOCK));
    int clo = fcntl(alias, F_DUPFD_CLOEXEC, 100);
    assert(clo >= 100 && fcntl(clo, F_GETFD) == FD_CLOEXEC);
    int plain = fcntl(clo, F_DUPFD, 100);
    assert(plain >= 100 && fcntl(plain, F_GETFD) == 0);
    assert(close(clo) == 0 && close(plain) == 0);
    assert(dup2(fd, fd) == fd);
    errno = 0;
    assert(dup3(fd, fd, 0) == -1 && errno == EINVAL);
    assert(dup2(-1, alias) == -1 && errno == EBADF);
    exchange(alias);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    assert(ep >= 0);
    control(ep, EPOLL_CTL_ADD, fd, EPOLLOUT, 1);
    control(ep, EPOLL_CTL_ADD, alias, EPOLLOUT, 2);
    events(ep, (1u << 1) | (1u << 2), 2);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *bad = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(bad != MAP_FAILED);
    char staged = 's';
    assert(write(fd, &staged, 1) == 1);
    assert(read(fd, bad, 1) == -1 && errno == EFAULT);
    assert(close(fd) == 0);
    staged = 0;
    assert(read(alias, &staged, 1) == 1 && staged == 's');
    exchange(alias); // First close must neither send FIN nor discard input state.
    events(ep, (1u << 1) | (1u << 2), 2);
    int reused = connected();
    if (reused != fd) {
        assert(dup2(reused, fd) == fd);
        assert(close(reused) == 0);
    }
    struct epoll_event event = {.events = EPOLLOUT, .data.u64 = 3};
    assert(epoll_ctl(ep, EPOLL_CTL_MOD, fd, &event) == -1 && errno == ENOENT);
    control(ep, EPOLL_CTL_ADD, fd, EPOLLOUT, 3);
    events(ep, (1u << 1) | (1u << 2) | (1u << 3), 3);
    control(ep, EPOLL_CTL_DEL, alias, 0, 0);
    events(ep, (1u << 1) | (1u << 3), 2);
    assert(close(alias) == 0); // Final alias removes even the closed-fd registration.
    events(ep, 1u << 3, 1);

    control(ep, EPOLL_CTL_MOD, fd, EPOLLOUT | EPOLLONESHOT, 4);
    assert(epoll_wait(ep, bad, 1, 0) == -1 && errno == EFAULT);
    events(ep, 1u << 4, 1); // Faulted copyout must not disarm.
    struct epoll_event out[8];
    assert(epoll_wait(ep, out, 8, 0) == 0);
    control(ep, EPOLL_CTL_MOD, fd, EPOLLOUT | EPOLLONESHOT, 5);
    events(ep, 1u << 5, 1);
    assert(epoll_wait(ep, out, 8, 0) == 0);
    control(ep, EPOLL_CTL_MOD, fd, EPOLLOUT, 6);
    events(ep, 1u << 6, 1);
    events(ep, 1u << 6, 1); // LT remains armed.
    int one = dup(fd);
    assert(one >= 0);
    control(ep, EPOLL_CTL_ADD, one, EPOLLOUT | EPOLLONESHOT, 8);
    control(ep, EPOLL_CTL_MOD, fd, EPOLLOUT | EPOLLONESHOT, 9);
    assert(epoll_wait(ep, bad, 2, 0) == -1 && errno == EFAULT);
    if (managed) {
        void *partial = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(partial != MAP_FAILED);
        assert(mprotect((char *)partial + page, page, PROT_NONE) == 0);
        void *end = (char *)partial + page - sizeof(struct epoll_event);
        assert(epoll_wait(ep, end, 2, 0) == -1 && errno == EFAULT);
        assert(munmap(partial, page * 2) == 0);
    }
    events(ep, (1u << 8) | (1u << 9), 2);
    assert(epoll_wait(ep, out, 8, 0) == 0);
    control(ep, EPOLL_CTL_MOD, one, EPOLLOUT | EPOLLONESHOT, 10);
    events(ep, 1u << 10, 1);
    assert(epoll_wait(ep, out, 8, 0) == 0);
    control(ep, EPOLL_CTL_DEL, one, 0, 0);
    assert(close(one) == 0);
    control(ep, EPOLL_CTL_MOD, fd, EPOLLOUT, 6);
    assert(munmap(bad, page) == 0);
    if (managed) {
        assert(dup(ep) == -1 && errno == EOPNOTSUPP);
        event.events = EPOLLOUT | EPOLLET;
        assert(epoll_ctl(ep, EPOLL_CTL_MOD, fd, &event) == -1 && errno == EOPNOTSUPP);
    }

    int native = eventfd(0, EFD_CLOEXEC);
    assert(native >= 0);
    control(ep, EPOLL_CTL_ADD, native, EPOLLIN, 7);
    uint64_t value = 1;
    assert(write(native, &value, sizeof(value)) == sizeof(value));
    int n = epoll_wait(ep, out, 8, 1000);
    assert(n == 2);
    unsigned seen = 0;
    for (int i = 0; i < n; ++i) seen |= 1u << out[i].data.u64;
    assert(seen == ((1u << 6) | (1u << 7)));
    assert(read(native, &value, sizeof(value)) == sizeof(value));

    int target = connected();
    assert(dup2(-1, target) == -1 && errno == EBADF);
    exchange(target);
    assert(dup3(fd, target, O_CLOEXEC) == target);
    assert(fcntl(target, F_GETFD) == FD_CLOEXEC);
    exchange(target); // Managed target's previous OFD was closed.
    assert(dup2(native, target) == target); // Native over managed alias.
    assert(fcntl(target, F_GETFD) == 0);
    assert(write(target, &value, sizeof(value)) == sizeof(value));
    assert(read(native, &value, sizeof(value)) == sizeof(value));
    assert(dup2(fd, target) == target); // Managed over native.
    exchange(target);
    assert(dup2(fd, target) == target); // Another alias of the same OFD.

    // Force a kernel allocation failure and verify adapter slot rollback.
    struct rlimit saved, limited;
    assert(getrlimit(RLIMIT_NOFILE, &saved) == 0);
    limited = saved;
    limited.rlim_cur = 0;
    assert(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    assert(dup(fd) == -1 && errno == EMFILE);
    assert(dup2(fd, target) == -1 && errno == EBADF);
    assert(setrlimit(RLIMIT_NOFILE, &saved) == 0);
    exchange(target);

    if (managed) {
        int aliases[512], count = 0;
        while (count < 512) {
            int next = dup(fd);
            if (next < 0) { assert(errno == EMFILE); break; }
            aliases[count++] = next;
        }
        assert(count == 510); // fd + target occupy two tracked slots.
        int probe = fcntl(native, F_DUPFD_CLOEXEC, 0);
        assert(probe >= 0 && close(probe) == 0);
        for (int i = 0; i < 16; ++i) {
            assert(dup(fd) == -1 && errno == EMFILE);
            assert(socket(AF_INET, SOCK_STREAM, 0) == -1 && errno == EMFILE);
        }
        int after = fcntl(native, F_DUPFD_CLOEXEC, 0);
        assert(after == probe && close(after) == 0); // No retained-token fd leak.
        assert(fcntl(fd, F_DUPFD, -1) == -1 && errno == EINVAL);
        assert(fcntl(fd, F_DUPFD, 0x7fffffff) == -1 && errno == EINVAL);
        assert(dup2(fd, -1) == -1 && errno == EBADF);
        assert(dup3(fd, target, O_NONBLOCK) == -1 && errno == EINVAL);
        assert(dup2(fd, native) == -1 && errno == EMFILE);
        assert(write(native, &value, sizeof(value)) == sizeof(value));
        assert(read(native, &value, sizeof(value)) == sizeof(value));
        // Replacement at capacity needs no extra slot and must be atomic.
        assert(dup2(fd, target) == target);
        assert(dup2(-1, target) == -1 && errno == EBADF);
        assert(close(aliases[--count]) == 0);
        int next = dup(fd);
        assert(next >= 0 && close(next) == 0);
        while (count) assert(close(aliases[--count]) == 0);
    }
    assert(close(target) == 0);
    exchange(fd);
    assert(close(fd) == 0);
    assert(epoll_wait(ep, out, 8, 0) == 0);
    assert(close(ep) == 0 && close(native) == 0);
    return 0;
}
