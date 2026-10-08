#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned char data[150000];
static volatile sig_atomic_t broken_pipes;
static void broken_pipe(int signal_number) { (void)signal_number; ++broken_pipes; }
static int connect_to(const char *host) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(16406)};
    assert(inet_pton(AF_INET, host, &a.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    return fd;
}
static void freebind_check(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), alias = dup(fd), value = -1;
    socklen_t len = sizeof(value);
    assert(fd >= 0 && alias >= 0);
    assert(getsockopt(fd, SOL_IP, IP_FREEBIND, &value, &len) == 0 && value == 0);
    struct sockaddr_in a = {.sin_family = AF_INET};
    assert(inet_pton(AF_INET, "198.51.100.17", &a.sin_addr) == 1);
    assert(bind(fd, (struct sockaddr *)&a, sizeof(a)) == -1 && errno == EADDRNOTAVAIL);
    unsigned char byte = 1;
    assert(setsockopt(alias, SOL_IP, IP_FREEBIND, &byte, 1) == 0);
    assert(getsockopt(fd, SOL_IP, IP_FREEBIND, &value, &len) == 0 && value == 1);
    value = 0;
    assert(setsockopt(fd, SOL_IP, IP_FREEBIND, &value, sizeof(value)) == 0);
    assert(bind(fd, (struct sockaddr *)&a, sizeof(a)) == -1 && errno == EADDRNOTAVAIL);
    value = 1;
    assert(setsockopt(alias, SOL_IP, IP_FREEBIND, &value, sizeof(value)) == 0);
    assert(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    assert(listen(fd, 1) == 0);
    struct sockaddr_in name; len = sizeof(name);
    assert(getsockname(fd, (struct sockaddr *)&name, &len) == 0);
    assert(name.sin_addr.s_addr == a.sin_addr.s_addr && name.sin_port != 0);
    close(alias); close(fd);
}
struct bridge { int in, out; ssize_t result; };
static void *bridge(void *arg) {
    struct bridge *b = arg;
    b->result = splice(b->in, NULL, b->out, NULL, 5, 0);
    return NULL;
}
static void cancellation_check(void) {
    int p[2], s[2];
    assert(pipe(p) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
    struct bridge b = {p[0], s[0], -1}; pthread_t thread;
    assert(pthread_create(&thread, NULL, bridge, &b) == 0);
    usleep(50000);
    assert(pthread_cancel(thread) == 0);
    void *result;
    assert(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
    close(p[0]); close(p[1]); close(s[0]); close(s[1]);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    signal(SIGPIPE, broken_pipe);
    for (size_t i = 0; i < sizeof(data); ++i) data[i] = i % 251;
    freebind_check(); cancellation_check();
    int file = memfd_create("ntcp-file-transfer", MFD_CLOEXEC);
    assert(file >= 0 && write(file, data, sizeof(data)) == sizeof(data));
    for (int test = 0; test < 15; ++test) {
        fprintf(stderr, "transfer case %d\n", test);
        int fd = connect_to(argv[1]);
        if (test == 0) assert(ftruncate(file, 5) == 0);
        if (test == 2) assert(pwrite(file, data, sizeof(data), 0) == sizeof(data));
        assert(lseek(file, 0, SEEK_SET) == 0);
        if (test == 0) {
            assert(sendfile(fd, file, NULL, 5) == 5);
            assert(lseek(file, 0, SEEK_CUR) == 5);
        } else if (test == 1) {
            off_t offset = 0;
            assert(sendfile(fd, file, &offset, 5) == 5 && offset == 5);
            assert(lseek(file, 0, SEEK_CUR) == 0);
            offset = 5;
            assert(sendfile(fd, file, &offset, 5) == 0 && offset == 5);
            assert(sendfile(fd, file, &offset, SIZE_MAX) == -1 && errno == EINVAL && offset == 5);
            offset = -1;
            assert(sendfile(fd, file, &offset, 5) == -1 && errno == EINVAL && offset == -1);
        } else if (test == 2 || test == 3) {
            int alias = dup(fd), fa = dup(file);
            assert(alias >= 0 && fa >= 0);
            assert(dup2(fa, fd) == fd); // Managed-over-native replacement must preserve alias.
            off64_t offset = 0;
            while (offset < (off64_t)sizeof(data)) {
                ssize_t n = sendfile64(alias, fa, test == 2 ? &offset : NULL, test == 2 ? (size_t)INT64_MAX : sizeof(data) - offset);
                assert(n > 0);
                if (test == 3) offset += n;
            }
            assert(lseek(file, 0, SEEK_CUR) == (test == 2 ? 0 : (off_t)sizeof(data)));
            close(fd); fd = alias; close(fa);
        } else if (test == 4) {
            assert(sendfile(fd, file, (off_t *)(uintptr_t)1, 5) == -1 && errno == EFAULT);
            assert(lseek(file, 0, SEEK_CUR) == 0);
            assert(sendfile(fd, file, NULL, 5) == 5);
        } else if (test == 5) {
            int p[2]; assert(pipe(p) == 0);
            off64_t offset = 0;
            assert(splice(p[0], &offset, fd, NULL, 1, SPLICE_F_NONBLOCK) == -1 && errno == ESPIPE);
            assert(splice(p[0], NULL, fd, &offset, 1, SPLICE_F_NONBLOCK) == -1 && errno == EINVAL);
            assert(splice(p[0], NULL, fd, (off64_t *)(uintptr_t)1, 1, SPLICE_F_NONBLOCK) == -1 && errno == EFAULT);
            assert(splice(p[1], NULL, fd, NULL, 1, SPLICE_F_NONBLOCK) == -1 && errno == EBADF);
            assert(splice(fd, NULL, p[0], NULL, 1, SPLICE_F_NONBLOCK) == -1 && errno == EBADF);
            assert(splice(p[0], NULL, fd, NULL, 1, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
            assert(splice(p[0], NULL, fd, NULL, 1, 0x80000000) == -1 && errno == EINVAL);
            size_t at = 0;
            while (at < sizeof(data)) {
                size_t chunk = sizeof(data) - at; if (chunk > 4096) chunk = 4096;
                assert(write(p[1], data + at, chunk) == (ssize_t)chunk);
                size_t sent = 0;
                while (sent < chunk) {
                    ssize_t n = splice(p[0], NULL, fd, NULL, chunk - sent, SPLICE_F_MORE);
                    assert(n > 0); sent += n;
                }
                at += chunk;
            }
            close(p[1]);
            assert(splice(p[0], NULL, fd, NULL, 1, 0) == 0);
            assert(fcntl(p[0], F_GETFL) == O_RDONLY);
            close(p[0]);
        } else if (test == 6 || test == 7) {
            int value = 4096; assert(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) == 0);
            assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
            int p[2]; assert(pipe(p) == 0);
            size_t accepted = 0; int blocked = 0;
            off_t offset = 0;
            while (accepted < sizeof(data)) {
                ssize_t n;
                if (test == 6) {
                    off_t before = offset;
                    n = sendfile(fd, file, &offset, sizeof(data) - accepted);
                    if (n < 0) assert(offset == before);
                } else {
                    int queued; assert(ioctl(p[0], FIONREAD, &queued) == 0);
                    if (!queued) {
                        size_t chunk = sizeof(data) - accepted; if (chunk > 4096) chunk = 4096;
                        assert(write(p[1], data + accepted, chunk) == (ssize_t)chunk);
                        queued = chunk;
                    }
                    n = splice(p[0], NULL, fd, NULL, queued, SPLICE_F_NONBLOCK);
                    if (n < 0) { int after; assert(ioctl(p[0], FIONREAD, &after) == 0 && after == queued); }
                }
                if (n < 0) { assert(errno == EAGAIN); ++blocked; usleep(1000); }
                else { assert(n > 0); accepted += n; }
            }
            assert(blocked > 0);
            close(p[0]); close(p[1]);
        } else if (test == 8) {
            int p[2]; assert(pipe2(p, O_NONBLOCK) == 0);
            unsigned char marker[4096]; memset(marker, 0xfe, sizeof(marker));
            size_t fill = 0; ssize_t n;
            while ((n = write(p[1], marker, sizeof(marker))) > 0) fill += n;
            assert(errno == EAGAIN);
            usleep(100000);
            assert(splice(fd, NULL, p[1], NULL, 5, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
            assert(read(p[0], marker, sizeof(marker)) == sizeof(marker)); fill -= sizeof(marker);
            ssize_t first = splice(fd, NULL, p[1], NULL, sizeof(data), SPLICE_F_NONBLOCK);
            assert(first > 0 && first <= (ssize_t)sizeof(marker));
            while (fill) { n = read(p[0], marker, fill < sizeof(marker) ? fill : sizeof(marker)); assert(n > 0); fill -= n; }
            assert(read(p[0], marker, first) == first && memcmp(marker, data, first) == 0);
            size_t received = first;
            while (received < sizeof(data)) {
                n = splice(fd, NULL, p[1], NULL, sizeof(data) - received, 0);
                if (n < 0) { assert(errno == EAGAIN); usleep(1000); continue; }
                assert(n > 0);
                unsigned char buf[65536]; assert(read(p[0], buf, n) == n);
                assert(memcmp(buf, data + received, n) == 0); received += n;
            }
            assert(fcntl(p[1], F_GETFL) & O_NONBLOCK);
            close(p[0]); close(p[1]);
        } else if (test == 9 || test == 10) {
            if (test == 9) assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
            int p[2]; assert(pipe(p) == 0);
            struct bridge b = {test == 9 ? p[0] : fd, test == 9 ? fd : p[1], -1};
            pthread_t thread; assert(pthread_create(&thread, NULL, bridge, &b) == 0);
            usleep(100000);
            int dummy = open("/dev/null", O_RDWR); assert(dummy >= 0);
            assert(dup2(dummy, fd) == fd);
            assert(dup2(dummy, test == 9 ? p[0] : p[1]) >= 0);
            if (test == 9) assert(write(p[1], data, 5) == 5);
            assert(pthread_join(thread, NULL) == 0 && b.result == 5);
            if (test == 10) { unsigned char buf[5]; assert(read(p[0], buf, 5) == 5 && memcmp(buf, data, 5) == 0); }
            close(dummy); close(p[0]); close(p[1]); close(fd);
            continue;
        } else if (test == 11) {
            int p[2]; assert(pipe(p) == 0);
            struct timeval timeout = {.tv_usec = 60000};
            assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
            if (getenv("NTCP_SOCKET_TUN")) {
                struct timespec begin, end;
                assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
                assert(splice(p[0], NULL, fd, NULL, 5, 0) == -1 && errno == EAGAIN);
                assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
                double elapsed = end.tv_sec - begin.tv_sec + (end.tv_nsec - begin.tv_nsec) / 1e9;
                assert(elapsed >= .04 && elapsed < 1);
            }
            assert(splice(p[0], NULL, fd, NULL, 5, SPLICE_F_NONBLOCK) == -1 && errno == EAGAIN);
            assert(shutdown(fd, SHUT_WR) == 0);
            assert(write(p[1], data, 5) == 5);
            sig_atomic_t before = broken_pipes;
            assert(splice(p[0], NULL, fd, NULL, 5, 0) == -1 && errno == EPIPE);
            assert(broken_pipes == before + 1);
            assert(sendfile(fd, file, NULL, 5) == -1 && errno == EPIPE);
            assert(broken_pipes == before + 2 && lseek(file, 0, SEEK_CUR) == 0);
            int queued; assert(ioctl(p[0], FIONREAD, &queued) == 0 && queued == 5);
            close(p[0]); close(p[1]);
        }
        if (test == 12) {
            off_t *offset = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            assert(offset != MAP_FAILED); *offset = 0;
            assert(mprotect(offset, 4096, PROT_READ) == 0);
            assert(sendfile(fd, file, offset, 5) == -1 && errno == EFAULT && *offset == 0);
            assert(lseek(file, 0, SEEK_CUR) == 0);
            assert(munmap(offset, 4096) == 0);
            assert(sendfile(fd, file, (off_t *)(uintptr_t)1, 0) == -1 && errno == EFAULT);
        }
        if (test == 13) {
            int p[2]; assert(pipe(p) == 0); close(p[0]);
            usleep(100000);
            sig_atomic_t before = broken_pipes;
            assert(splice(fd, NULL, p[1], NULL, 5, 0) == -1 && errno == EPIPE);
            assert(broken_pipes == before + 1);
            unsigned char bytes[5]; assert(read(fd, bytes, 5) == 5 && memcmp(bytes, data, 5) == 0);
            close(p[1]);
        }
        if (test == 14) {
            int p[2]; assert(pipe2(p, O_NONBLOCK) == 0);
            unsigned char marker[4096]; memset(marker, 0xfe, sizeof(marker));
            size_t fill = 0; ssize_t n;
            while ((n = write(p[1], marker, sizeof(marker))) > 0) fill += n;
            assert(errno == EAGAIN);
            assert(fcntl(p[1], F_SETFL, 0) == 0);
            assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
            usleep(100000);
            struct bridge b = {fd, p[1], -1}; pthread_t thread;
            assert(pthread_create(&thread, NULL, bridge, &b) == 0);
            usleep(100000);
            assert(read(p[0], marker, sizeof(marker)) == sizeof(marker)); fill -= sizeof(marker);
            assert(pthread_join(thread, NULL) == 0 && b.result == 5);
            while (fill) { n = read(p[0], marker, fill < sizeof(marker) ? fill : sizeof(marker)); assert(n > 0); fill -= n; }
            assert(read(p[0], marker, 5) == 5 && memcmp(marker, data, 5) == 0);
            assert(fcntl(p[1], F_GETFL) == O_WRONLY);
            close(p[0]); close(p[1]);
        }
        if (test != 11) assert(shutdown(fd, SHUT_WR) == 0);
        unsigned char byte;
        while (read(fd, &byte, 1) > 0) {}
        close(fd);
    }
    close(file);
    return 0;
}
