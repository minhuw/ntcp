#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t pipes;
static void broken(int sig) { (void)sig; pipes++; }
static double now(void) { struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC, &t)); return t.tv_sec + t.tv_nsec / 1e9; }
static int connection(const char *host) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), size = 1000;
    assert(fd >= 0);
    assert(!setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(16405) };
    assert(inet_pton(AF_INET, host, &addr.sin_addr) == 1);
    assert(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
    return fd;
}
static void phases(int fd, unsigned last) {
    unsigned stages = 0, zc = 0;
    double end = now() + 3;
    while (now() < end && (stages != 7 || zc != 1)) {
        char control[512];
        struct msghdr m = { .msg_control = control, .msg_controllen = sizeof(control) };
        ssize_t n = recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (n < 0) { assert(errno == EAGAIN); usleep(1000); continue; }
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level != SOL_IP || c->cmsg_type != IP_RECVERR) continue;
            struct sock_extended_err *e = (void *)CMSG_DATA(c);
            if (e->ee_origin == SO_EE_ORIGIN_ZEROCOPY) {
                assert(e->ee_info == 0 && e->ee_data == 0 && zc == 0); zc++;
            } else {
                assert(e->ee_origin == SO_EE_ORIGIN_TIMESTAMPING);
                assert(e->ee_data == last && e->ee_info <= 2);
                unsigned bit = 1u << e->ee_info;
                assert(!(stages & bit)); stages |= bit;
            }
        }
    }
    assert(stages == 7 && zc == 1);
    char control[512];
    struct msghdr m = { .msg_control = control, .msg_controllen = sizeof(control) };
    assert(recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN);
}
static void *stop_write(void *arg) { usleep(60000); assert(!shutdown(*(int *)arg, SHUT_WR)); return NULL; }
int main(int argc, char **argv) {
    assert(argc == 2); alarm(25); signal(SIGPIPE, broken);
    size_t count = 150000;
    char *bytes = malloc(4 * 1024 * 1024); assert(bytes);
    for (size_t i = 0; i < 4 * 1024 * 1024; ++i) bytes[i] = (char)(i % 251);
    for (int family = 0; family < 5; ++family) {
        int fd = connection(argv[1]);
        struct iovec v[] = { {bytes, 71003}, {bytes + 71003, count - 71003} };
        struct msghdr m = { .msg_iov = v, .msg_iovlen = 2 };
        if (family == 4) {
            int one = 1, bits = SOF_TIMESTAMPING_TX_SCHED | SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_ACK | SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_OPT_ID | SOF_TIMESTAMPING_OPT_TSONLY;
            assert(!setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)));
            assert(!setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &bits, sizeof(bits)));
        }
        ssize_t n = family == 0 ? write(fd, bytes, count) :
            family == 1 ? send(fd, bytes, count, 0) :
            family == 2 ? sendto(fd, bytes, count, 0, NULL, 0) :
            family == 3 ? writev(fd, v, 2) : sendmsg(fd, &m, MSG_ZEROCOPY | MSG_EOR);
        assert(n == (ssize_t)count);
        if (family == 4) phases(fd, count - 1);
        assert(!close(fd));
    }
    size_t page = (size_t)sysconf(_SC_PAGESIZE), valid = 24 * page;
    void *mapping = mmap(NULL, valid + page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED); memset(mapping, 19, valid);
    assert(!mprotect((char *)mapping + valid, page, PROT_NONE));
    for (int vector = 0; vector < 2; ++vector) {
        int fd = connection(argv[1]);
        struct iovec v[] = { {mapping, valid}, {(char *)mapping + valid, page} };
        ssize_t n = vector ? writev(fd, v, 2) : write(fd, mapping, valid + page);
        assert(n > 0 && (size_t)n <= valid); close(fd);
    }
    munmap(mapping, valid + page);
    int fd = connection(argv[1]), alias = dup(fd); assert(alias >= 0);
    assert(!fcntl(alias, F_SETFL, O_NONBLOCK)); assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
    ssize_t n = send(fd, bytes, count, 0); assert(n > 0 && (size_t)n < count);
    for (int i = 0; i < 100; ++i) {
        n = writev(alias, (struct iovec[]){{bytes, count}}, 1);
        if (n < 0) { assert(errno == EAGAIN); break; }
        assert(i != 99);
    }
    close(alias); close(fd);
    fd = connection(argv[1]);
    struct timeval timeout = { .tv_usec = 120000 };
    assert(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    double start = now(); n = write(fd, bytes, 4 * 1024 * 1024); double elapsed = now() - start;
    assert(n > 0 && n < 4 * 1024 * 1024 && elapsed >= .08 && elapsed < .5);
    printf("timeout prefix=%zd elapsed=%.3f\n", n, elapsed); close(fd);
    size_t huge = ((size_t)INT_MAX & ~(page - 1)) + page;
    mapping = mmap(NULL, huge, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(mapping != MAP_FAILED); fd = connection(argv[1]);
    n = send(fd, mapping, huge, MSG_DONTWAIT); assert(n > 0 && (size_t)n < huge);
    close(fd); munmap(mapping, huge);
    fd = connection(argv[1]); pthread_t thread;
    assert(!pthread_create(&thread, NULL, stop_write, &fd));
    n = send(fd, bytes, 4 * 1024 * 1024, 0);
    assert(n > 0 && n < 4 * 1024 * 1024 && pipes == 0);
    assert(!pthread_join(thread, NULL));
    assert(send(fd, bytes, 1, 0) == -1 && errno == EPIPE && pipes == 1);
    assert(send(fd, bytes, 1, MSG_NOSIGNAL) == -1 && errno == EPIPE && pipes == 1);
    close(fd); free(bytes);
    puts("PASS large scalar/vector sends, faults, timeout, shared flags, cap, SIGPIPE, single timestamp/zerocopy");
}
