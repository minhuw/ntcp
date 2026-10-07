#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void elapsed(double start) {
    double seconds = now() - start;
    assert(seconds >= .07 && seconds < 2.0);
}
static void timeout(int fd, int name, long usec) {
    struct timeval t = {0, usec};
    assert(setsockopt(fd, SOL_SOCKET, name, &t, sizeof(t)) == 0);
}
static struct sockaddr_in address(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    assert(inet_pton(AF_INET, ip, &a.sin_addr) == 1);
    return a;
}
static int connected(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in a = address(ip, port);
    assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    timeout(fd, SO_RCVTIMEO, 150000);
    timeout(fd, SO_SNDTIMEO, 150000);
    return fd;
}
static void options(int fd, int virtual) {
    struct timeval t = {0};
    socklen_t n = sizeof(t);
    assert(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, &n) == 0);
    assert(n == sizeof(t) && t.tv_sec == 0 && t.tv_usec >= 150000 && t.tv_usec < 170000);
    struct timeval bad = {1, 1000000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &bad, sizeof(bad)) == -1 && errno == EDOM);
    bad.tv_usec = -1;
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &bad, sizeof(bad)) == -1 && errno == EDOM);
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t) - 1) == -1 && errno == EINVAL);
    struct timeval check = {0};
    n = sizeof(check);
    assert(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &check, &n) == 0);
    assert(memcmp(&check, &t, sizeof(t)) == 0); /* invalid sets are transactional */
    n = 3;
    unsigned char short_value[4] = {0, 0, 0, 0x77};
    assert(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, short_value, &n) == 0);
    assert(n == 3 && short_value[3] == 0x77);
    n = 0;
    assert(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, short_value, &n) == 0 && n == 0);
    /* OLD and NEW Linux timeval ABIs on the supported 64-bit architectures. */
    int64_t pair[2] = {0, 123456};
    assert(setsockopt(fd, SOL_SOCKET, 66, pair, sizeof(pair)) == 0);
    n = sizeof(pair);
    assert(getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, pair, &n) == 0);
    assert(pair[0] == 0 && pair[1] >= 123456 && pair[1] < 140000);
    if (virtual) assert(pair[1] == 123456); /* exact microseconds, not jiffies */
    int64_t send_pair[2] = {0, 150000};
    assert(setsockopt(fd, SOL_SOCKET, 67, send_pair, sizeof(send_pair)) == 0);
    n = sizeof(send_pair);
    assert(getsockopt(fd, SOL_SOCKET, 67, send_pair, &n) == 0);
    assert(send_pair[0] == 0 && send_pair[1] >= 150000 && send_pair[1] < 170000);
    if (virtual) {
        int64_t extreme[2] = {INT64_MAX, 0};
        assert(setsockopt(fd, SOL_SOCKET, 66, extreme, sizeof(extreme)) == -1 && errno == EINVAL);
        /* Largest representable microsecond budget must not overflow Instant. */
        extreme[0] = (int64_t)(UINT64_MAX / 1000000);
        extreme[1] = (int64_t)(UINT64_MAX % 1000000);
        assert(setsockopt(fd, SOL_SOCKET, 66, extreme, sizeof(extreme)) == 0);
        n = sizeof(pair);
        assert(getsockopt(fd, SOL_SOCKET, 66, pair, &n) == 0);
        assert(memcmp(pair, extreme, sizeof(pair)) == 0);
    }
    pair[0] = -1;
    pair[1] = 0;
    assert(setsockopt(fd, SOL_SOCKET, 66, pair, sizeof(pair)) == 0);
    n = sizeof(pair);
    assert(getsockopt(fd, SOL_SOCKET, 66, pair, &n) == 0);
    assert(pair[0] == 0 && pair[1] == 0);
    timeout(fd, SO_RCVTIMEO, 150000);
}
static void *blocked_reader(void *arg) {
    char c;
    assert(recv(*(int *)arg, &c, 1, 0) == -1 && errno == EAGAIN);
    return NULL;
}
static void stream(const char *ip, int virtual) {
    int fd = connected(ip, 16400);
    options(fd, virtual);
    char a[8] = {0}, b[8] = {0};
    assert(recv(fd, a, 6, MSG_PEEK) == 6 && memcmp(a, "abcdef", 6) == 0);
    assert(recv(fd, b, 6, MSG_PEEK) == 6 && memcmp(a, b, 6) == 0);
    void *fault = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(fault != MAP_FAILED);
    assert(recv(fd, fault, 3, MSG_PEEK) == -1 && errno == EFAULT);
    socklen_t address_size = sizeof(struct sockaddr_in);
    if (virtual) {
        assert(recvfrom(fd, a, 6, MSG_PEEK, fault, &address_size) == -1 && errno == EFAULT);
    } else {
        /* Linux TCP recvfrom does not emit a source address. */
        assert(recvfrom(fd, a, 6, MSG_PEEK, fault, &address_size) == 6 && address_size == 0);
    }
    struct sockaddr_in peer;
    address_size = sizeof(peer);
    assert(recvfrom(fd, a, 6, MSG_PEEK, (struct sockaddr *)&peer, &address_size) == 6);
    assert(memcmp(a, "abcdef", 6) == 0 && address_size == (virtual ? sizeof(peer) : 0));
    assert(recv(fd, fault, 3, 0) == -1 && errno == EFAULT);
    /* Faulted normal reads may have bounded staging; those bytes must peek. */
    assert(recv(fd, a, 3, MSG_PEEK) == 3 && memcmp(a, "abc", 3) == 0);
    struct iovec v[2] = {{a, 2}, {b, 4}};
    struct msghdr m = {.msg_iov = v, .msg_iovlen = 2};
    ssize_t got = recvmsg(fd, &m, MSG_PEEK);
    assert(got >= 3 && got <= 6 && memcmp(a, "ab", 2) == 0);
    assert(memcmp(b, "cdef", (size_t)got - 2) == 0 && m.msg_flags == 0);
    void *saved = v[1].iov_base;
    v[1].iov_base = fault;
    assert(recvmsg(fd, &m, MSG_PEEK) == -1 && errno == EFAULT);
    v[1].iov_base = saved;
    ssize_t repeated = recvmsg(fd, &m, MSG_PEEK);
    assert(repeated == got);
    size_t offset = 0;
    while (offset < 6) {
        ssize_t n = read(fd, a + offset, 6 - offset);
        assert(n > 0);
        offset += (size_t)n;
    }
    assert(memcmp(a, "abcdef", 6) == 0);
    assert(munmap(fault, 4096) == 0);
    double start = now();
    assert(recv(fd, a, sizeof(a), MSG_PEEK) == -1 && errno == EAGAIN);
    elapsed(start);
    start = now();
    assert(recv(fd, a, sizeof(a), MSG_DONTWAIT | MSG_PEEK) == -1 && errno == EAGAIN);
    assert(now() - start < .07);
    assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    start = now();
    assert(read(fd, a, sizeof(a)) == -1 && errno == EAGAIN);
    assert(now() - start < .07);
    assert(fcntl(fd, F_SETFL, 0) == 0);
    struct pollfd p = {.fd = fd, .events = POLLIN};
    start = now();
    assert(poll(&p, 1, 300) == 0 && now() - start >= .22);
    if (virtual) {
        /* A second reader's shorter budget includes contention on Input. */
        timeout(fd, SO_RCVTIMEO, 350000);
        pthread_t thread;
        assert(pthread_create(&thread, NULL, blocked_reader, &fd) == 0);
        usleep(50000);
        timeout(fd, SO_RCVTIMEO, 150000);
        start = now();
        assert(recv(fd, a, sizeof(a), 0) == -1 && errno == EAGAIN);
        assert(now() - start >= .07 && now() - start < .28);
        assert(pthread_join(thread, NULL) == 0);
    }
    assert(send(fd, "P", 1, MSG_NOSIGNAL) == 1);
    start = now();
    assert(recv(fd, a, sizeof(a), 0) == 3 && memcmp(a, "xyz", 3) == 0);
    assert(now() - start < .5); /* partial data, not an artificial full-buffer wait */
    assert(recv(fd, a, sizeof(a), MSG_PEEK) == 0);
    assert(read(fd, a, sizeof(a)) == 0);
    if (virtual) {
        assert(recv(fd, a, sizeof(a), MSG_WAITALL) == -1 && errno == EOPNOTSUPP);
        assert(recv(fd, a, sizeof(a), MSG_TRUNC) == -1 && errno == EOPNOTSUPP);
    }
    assert(close(fd) == 0);
}
static void accept_controls(const char *local) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    int yes = 1;
    assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == 0);
    struct sockaddr_in a = address(local, 16401);
    assert(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(fd, 4) == 0);
    timeout(fd, SO_RCVTIMEO, 150000);
    timeout(fd, SO_SNDTIMEO, 150000);
    double start = now();
    assert(accept(fd, NULL, NULL) == -1 && errno == EAGAIN);
    elapsed(start);
    puts("ACCEPT");
    fflush(stdout);
    /* Wait for a queued child, then mutate through an alias before accept. */
    struct pollfd queued = {.fd = fd, .events = POLLIN};
    assert(poll(&queued, 1, 3000) == 1 && (queued.revents & POLLIN));
    int alias = dup(fd);
    assert(alias >= 0);
    timeout(alias, SO_RCVTIMEO, 350000);
    timeout(alias, SO_SNDTIMEO, 450000);
    assert(close(alias) == 0);
    int child = accept(fd, NULL, NULL);
    assert(child >= 0);
    struct timeval t = {0};
    for (int direction = 0; direction < 2; ++direction) {
        socklen_t n = sizeof(t);
        assert(getsockopt(child, SOL_SOCKET, direction ? SO_SNDTIMEO : SO_RCVTIMEO, &t, &n) == 0);
        assert(n == sizeof(t) && t.tv_sec == 0 && t.tv_usec >= 150000 && t.tv_usec < 170000);
    }
    assert(close(child) == 0 && close(fd) == 0);
}
static void reset_controls(const char *ip) {
    int fd = connected(ip, 16402);
    usleep(250000);
    char a[8];
    for (int i = 0; i < 2; ++i)
        assert(recv(fd, a, sizeof(a), MSG_PEEK) == 3 && memcmp(a, "rst", 3) == 0);
    assert(read(fd, a, sizeof(a)) == 3 && memcmp(a, "rst", 3) == 0);
    assert(recv(fd, a, sizeof(a), MSG_PEEK) == -1 && errno == ECONNRESET);
    assert(recv(fd, a, sizeof(a), MSG_PEEK) == 0);
    assert(close(fd) == 0);
}
static void send_controls(const char *ip) {
    int fd = connected(ip, 16400);
    char bytes[65536] = {0};
    size_t total = 0;
    double start = now();
    for (int i = 0; i < 1024; ++i) {
        start = now();
        ssize_t n = send(fd, bytes, sizeof(bytes), MSG_NOSIGNAL);
        if (n < 0) {
            assert(errno == EAGAIN);
            elapsed(start);
            break;
        }
        assert(n > 0);
        total += (size_t)n;
        assert(i != 1023);
    }
    assert(total > 0);
    start = now();
    assert(send(fd, bytes, sizeof(bytes), MSG_NOSIGNAL | MSG_DONTWAIT) == -1 && errno == EAGAIN);
    assert(now() - start < .07);
    assert(close(fd) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 4);
    int virtual = strcmp(argv[3], "virtual") == 0;
    alarm(20);
    stream(argv[1], virtual);
    accept_controls(argv[2]);
    reset_controls(argv[1]);
    send_controls(argv[1]);
    if (virtual) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(fd >= 0);
        timeout(fd, SO_SNDTIMEO, 150000);
        struct sockaddr_in a = address("10.73.0.99", 16403);
        double start = now();
        assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == -1 && errno == EINPROGRESS);
        elapsed(start);
        assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == -1 && errno == EALREADY);
        int e = -1;
        socklen_t n = sizeof(e);
        assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &n) == 0 && e == 0);
        assert(close(fd) == 0);
    }
    puts("PASS: stream controls");
    return 0;
}
