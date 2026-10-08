#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/tcp.h>
#include <stddef.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef TCP_INQ
#define TCP_INQ 36
#endif
_Static_assert(offsetof(struct tcp_info, tcpi_last_data_recv) == 52, "last_data_recv ABI");
_Static_assert(offsetof(struct tcp_info, tcpi_notsent_bytes) == 144, "notsent ABI");
_Static_assert(offsetof(struct tcp_info, tcpi_busy_time) == 168, "busy ABI");
_Static_assert(offsetof(struct tcp_info, tcpi_rwnd_limited) == 176, "rwnd ABI");
_Static_assert(offsetof(struct tcp_info, tcpi_sndbuf_limited) == 184, "sndbuf ABI");
static void set(int fd, int option, int value) {
    assert(setsockopt(fd, IPPROTO_TCP, option, &value, sizeof(value)) == 0);
}
static int get(int fd, int option) {
    int value;
    socklen_t size = sizeof(value);
    assert(getsockopt(fd, IPPROTO_TCP, option, &value, &size) == 0 && size == 4);
    return value;
}
static void queue(int fd, int expected) {
    int bytes = 0;
    for (int i = 0; i < 5000; i++) {
        assert(ioctl(fd, FIONREAD, &bytes) == 0);
        if (bytes == expected) return;
        usleep(1000);
    }
    fprintf(stderr, "queue: expected %d, got %d\n", expected, bytes);
    abort();
}
static void edge(int ep, uint32_t expected) {
    struct epoll_event event = {0};
    assert(epoll_wait(ep, &event, 1, 1000) == 1);
    assert(event.events == expected && event.data.u64 == 42);
    assert(epoll_wait(ep, &event, 1, 0) == 0);
}
static int inq(int fd, int flags, size_t count, size_t capacity) {
    char data[32] = {0};
    struct iovec vectors[2] = {{data, count / 2}, {data + count / 2, count - count / 2}};
    _Alignas(struct cmsghdr) unsigned char control[32];
    memset(control, 0xaa, sizeof(control));
    struct msghdr msg = {.msg_iov = vectors, .msg_iovlen = 2,
                         .msg_control = control, .msg_controllen = capacity};
    ssize_t received = recvmsg(fd, &msg, flags);
    if (received != (ssize_t)count)
        fprintf(stderr, "recvmsg: flags=%d count=%zu capacity=%zu returned=%zd errno=%d\n", flags, count, capacity, received, errno);
    assert(received == (ssize_t)count);
    if (capacity < sizeof(struct cmsghdr)) {
        assert(msg.msg_controllen == 0 && (msg.msg_flags & MSG_CTRUNC));
        return -1;
    }
    size_t len = capacity < CMSG_LEN(4) ? capacity : CMSG_LEN(4);
    size_t used = capacity < CMSG_SPACE(4) ? capacity : CMSG_SPACE(4);
    assert(msg.msg_controllen == used);
    assert(!!(msg.msg_flags & MSG_CTRUNC) == (capacity < CMSG_LEN(4)));
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    assert(cm && cm->cmsg_len == len && cm->cmsg_level == IPPROTO_TCP && cm->cmsg_type == TCP_INQ);
    assert(control[len] == 0xaa); /* alignment padding is not overwritten */
    if (len < CMSG_LEN(4)) return -1;
    int result;
    memcpy(&result, CMSG_DATA(cm), 4);
    return result;
}
int main(int argc, char **argv) {
    assert(argc == 4);
    alarm(20);
    int managed = strstr(argv[3], "managed") != NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
    assert(inet_pton(AF_INET, argv[1], &addr.sin_addr) == 1);
    assert(connect(fd, (void *)&addr, sizeof(addr)) == 0);
    if (strstr(argv[3], "lowwater")) {
        int buffer = 65536;
        assert(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer, 4) == 0);
        set(fd, TCP_NOTSENT_LOWAT, 4000);
        char payload[4096] = {0};
        size_t sent = 0;
        for (int i = 0; i < 10000; i++) {
            /* EOR prevents Linux appending indefinitely to an existing skb:
               each next record must pass the notsent allocation gate. */
            ssize_t n = send(fd, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE | MSG_EOR);
            if (n == -1) {
                assert(errno == EAGAIN);
                struct pollfd p = {fd, POLLOUT, 0};
                if (poll(&p, 1, 20) == 0) break;
            } else {
                assert(n > 0);
                sent += (size_t)n;
            }
            assert(i != 9999);
        }
        assert(sent > 0);
        unsigned char info[280] = {0};
        socklen_t size = sizeof(info);
        assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &size) == 0 && size >= 148);
        uint32_t notsent;
        memcpy(&notsent, info + 144, 4);
        assert(notsent >= 2000);
        struct pollfd p = {fd, POLLOUT, 0};
        assert(poll(&p, 1, 0) == 0);
        assert(send(fd, payload, 1, MSG_DONTWAIT | MSG_NOSIGNAL) == -1 && errno == EAGAIN);
        set(fd, TCP_NOTSENT_LOWAT, -1);
        int writable = poll(&p, 1, 1000);
        if (writable != 1) fprintf(stderr, "lowwater: sent=%zu notsent=%u sndbuf-request=%d poll=%d revents=%d\n", sent, notsent, buffer, writable, p.revents);
        assert(writable == 1 && (p.revents & POLLOUT));
        close(fd);
        puts("PASS: notsent-only write backpressure and option-change writable wake");
        return 0;
    }
    assert(get(fd, TCP_NOTSENT_LOWAT) == 0); /* effective default UINT_MAX */
    for (int i = 0; i < 4; i++) {
        int value = (int[]){0, 4000, -1, INT_MIN}[i];
        set(fd, TCP_NOTSENT_LOWAT, value);
        assert(get(fd, TCP_NOTSENT_LOWAT) == value);
    }
    int value = 3;
    assert(setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &value, 3) == -1 && errno == EINVAL);
    set(fd, TCP_NOTSENT_LOWAT, 0);
    for (int bad = -1; bad <= 2; bad += 3) {
        assert(setsockopt(fd, IPPROTO_TCP, TCP_INQ, &bad, 4) == -1 && errno == EINVAL);
    }
    set(fd, TCP_INQ, 1);
    assert(get(fd, TCP_INQ) == 1);
    /* Short TCP_INFO ABI writes never touch the following byte. */
    for (socklen_t length = 0; length <= 280; length++) {
        unsigned char info[281];
        memset(info, 0xa5, sizeof(info));
        socklen_t used = length;
        assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &used) == 0 && used <= length);
        assert(info[used] == 0xa5);
    }
    unsigned char info[280];
    socklen_t negative = UINT_MAX;
    assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &negative) == -1 && errno == EINVAL);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    assert(ep >= 0);
    struct epoll_event registration = {.events = EPOLLIN | EPOLLOUT | EPOLLET, .data.u64 = 42};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &registration) == 0);
    edge(ep, EPOLLOUT);
    assert(send(fd, "A", 1, MSG_NOSIGNAL) == 1);
    queue(fd, 6);
    /* Failed ET output must not consume this edge. */
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(bad != MAP_FAILED);
    assert(epoll_wait(ep, bad, 1, 0) == -1 && errno == EFAULT);
    edge(ep, EPOLLIN | EPOLLOUT);
    for (size_t capacity = 0; capacity <= 25; capacity++) {
        int hint = inq(fd, MSG_PEEK, 3, capacity);
        if (capacity >= CMSG_LEN(4)) assert(hint == 6); /* post-PEEK is unchanged */
    }
    assert(inq(fd, 0, 2, 24) == 4);
    struct epoll_event event;
    assert(epoll_wait(ep, &event, 1, 0) == 0); /* partial drain is not an edge */
    int alias = dup(fd);
    assert(alias >= 0);
    assert(send(alias, "B", 1, MSG_NOSIGNAL) == 1);
    queue(fd, 7); /* new arrival while already readable */
    edge(ep, EPOLLIN | EPOLLOUT);
    registration.events |= EPOLLONESHOT;
    assert(epoll_ctl(ep, EPOLL_CTL_MOD, fd, &registration) == 0);
    int native = eventfd(1, EFD_CLOEXEC);
    assert(native >= 0);
    struct epoll_event native_registration = {.events = EPOLLIN | EPOLLONESHOT, .data.u64 = 84};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, native, &native_registration) == 0);
    assert(epoll_wait(ep, bad, 2, 0) == -1 && errno == EFAULT);
    struct epoll_event mixed[2];
    assert(epoll_wait(ep, mixed, 2, 0) == 2);
    assert(mixed[0].data.u64 + mixed[1].data.u64 == 126);
    for (int i = 0; i < 2; i++)
        assert(mixed[i].events == (mixed[i].data.u64 == 42 ? EPOLLIN | EPOLLOUT : EPOLLIN));
    struct epoll_event empty;
    assert(epoll_wait(ep, &empty, 1, 0) == 0);
    close(native);
    assert(epoll_ctl(ep, EPOLL_CTL_MOD, fd, &registration) == 0);
    edge(ep, EPOLLIN | EPOLLOUT); /* rearm without a new arrival */
    int alias_ep = epoll_create1(EPOLL_CLOEXEC);
    assert(alias_ep >= 0);
    struct epoll_event alias_registration = {.events = EPOLLIN | EPOLLET, .data.u64 = 42};
    assert(epoll_ctl(alias_ep, EPOLL_CTL_ADD, alias, &alias_registration) == 0);
    edge(alias_ep, EPOLLIN); /* independent per-registration seen state */
    if (managed) {
        char data[2];
        struct iovec v = {data, sizeof(data)};
        struct msghdr msg = {.msg_iov = &v, .msg_iovlen = 1, .msg_control = bad, .msg_controllen = 24};
        assert(recvmsg(fd, &msg, 0) == -1 && errno == EFAULT);
        queue(fd, 7); /* adapter additionally guarantees transactional EFAULT */
    }
    assert(inq(fd, 0, 7, 24) == 0);
    /* CORK holds the byte; NODELAY setting (even repeated) explicitly flushes. */
    set(fd, TCP_CORK, 1);
    assert(get(fd, TCP_CORK) == 1);
    assert(send(fd, "C", 1, MSG_NOSIGNAL) == 1);
    struct pollfd p = {fd, POLLIN, 0};
    assert(poll(&p, 1, 20) == 0);
    set(fd, TCP_NODELAY, 1);
    queue(fd, 1);
    assert(inq(fd, 0, 1, 24) == 0);
    assert(get(fd, TCP_CORK) == 1); /* NODELAY flush did not clear CORK */
    set(fd, TCP_CORK, 0);
    assert(send(fd, "D", 1, MSG_MORE | MSG_NOSIGNAL) == 1);
    assert(poll(&p, 1, 20) == 0);
    set(fd, TCP_NODELAY, 1);
    queue(fd, 1);
    assert(inq(fd, 0, 1, 24) == 0);
    set(fd, TCP_CORK, 1);
    assert(send(fd, "E", 1, MSG_NOSIGNAL) == 1);
    assert(poll(&p, 1, 20) == 0);
    set(fd, TCP_CORK, 0);
    queue(fd, 1);
    assert(inq(fd, 0, 1, 24) == 0);
    assert(send(fd, "F", 1, MSG_EOR | MSG_NOSIGNAL) == 1);
    queue(fd, 3);
    assert(poll(&p, 1, 1000) == 1);
    struct pollfd fin = {fd, POLLRDHUP, 0};
    assert(poll(&fin, 1, 1000) == 1 && (fin.revents & POLLRDHUP));
    assert(inq(fd, MSG_PEEK, 3, 24) == 4);
    assert(inq(fd, 0, 3, 24) == 1);
    assert(inq(fd, 0, 0, 24) == 1);
    close(fd); /* registration remains pinned by alias */
    edge(alias_ep, EPOLLIN);
    assert(epoll_ctl(ep, EPOLL_CTL_MOD, alias, &registration) == -1 && errno == ENOENT);
    close(alias);
    struct epoll_event closed;
    assert(epoll_wait(alias_ep, &closed, 1, 0) == 0);
    close(alias_ep);
    close(ep);
    munmap(bad, 4096);
    puts("PASS: ET, INQ CMSG ABI, uint lowwater, CORK/NODELAY/MORE/EOR, short TCP_INFO");
}
