// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "packetdrill.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <linux/sockios.h>
#include <linux/errqueue.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern long long ntcp_call(void *, int, int, int, int, const void *, size_t, void *, size_t, long long *);
extern void ntcp_free(void *);
extern long long ntcp_host_call(int, int, void *, size_t);
static int unsupported(const char *why) {
    fprintf(stderr, "NTCP_PACKETDRILL_UNSUPPORTED: %s\n", why);
    errno = ENOSYS; return -1;
}
static int bad(int error) { errno = error; return -1; }
// Bounded self-process copies report inaccessible or partially mapped buffers.
static int memory(void *local, const void *remote, size_t n, int writing) {
    if (!n) return 0;
    if ((uintptr_t)remote > INTPTR_MAX || n > INTPTR_MAX - (uintptr_t)remote) return bad(EFAULT);
    struct iovec l = {local, n}, r = {(void *)remote, n};
    long result = syscall(writing ? SYS_process_vm_writev : SYS_process_vm_readv,
                          syscall(SYS_getpid), &l, 1UL, &r, 1UL, 0UL);
    if (result < 0) return -1;
    return (size_t)result == n ? 0 : bad(EFAULT);
}
#define CALL(op, fd, a, b, in, n, out, m, aux) ntcp_call(u, op, fd, a, b, in, n, out, m, aux)
#define SIMPLE(op, fd, a, b) CALL(op, fd, a, b, NULL, 0, NULL, 0, NULL)
static int sock(void *u, int domain, int type, int protocol) {
    if (domain != AF_INET || (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != SOCK_STREAM || (protocol && protocol != IPPROTO_TCP)) return unsupported("socket: only IPv4 TCP");
    return SIMPLE(1, 0, type, 0);
}
static int address(void *u, int op, int fd, const struct sockaddr *p, socklen_t n) {
    if (!p) return bad(EFAULT);
    if (n < sizeof(struct sockaddr_in)) return bad(EINVAL);
    struct sockaddr_in addr; if (memory(&addr, p, sizeof(addr), 0)) return -1;
    if (addr.sin_family != AF_INET) return unsupported("address family");
    return CALL(op, fd, 0, 0, &addr, sizeof(addr), NULL, 0, NULL);
}
static int bind_socket(void *u, int fd, const struct sockaddr *p, socklen_t n) { return address(u, 2, fd, p, n); }
static int connect_socket(void *u, int fd, const struct sockaddr *p, socklen_t n) { return address(u, 5, fd, p, n); }
static int listen_socket(void *u, int fd, int backlog) { return SIMPLE(3, fd, backlog, 0); }
static int accept_socket(void *u, int fd, struct sockaddr *p, socklen_t *n) {
    if (p && !n) return bad(EFAULT);
    struct sockaddr_in addr;
    int result = CALL(4, fd, 0, 0, NULL, 0, &addr, sizeof(addr), NULL);
    if (result >= 0 && p) { size_t size = *n < sizeof(addr) ? *n : sizeof(addr); memcpy(p, &addr, size); *n = sizeof(addr); }
    return result;
}
static ssize_t read_socket(void *u, int fd, void *p, size_t n) { return CALL(6, fd, 0, 0, NULL, 0, p, n, NULL); }
static ssize_t write_socket(void *u, int fd, const void *p, size_t n) { return CALL(7, fd, 0, 0, p, n, NULL, 0, NULL); }
static ssize_t recv_socket(void *u, int fd, void *p, size_t n, int flags) {
    if (flags & ~MSG_DONTWAIT) return unsupported("recv flags");
    return CALL(6, fd, flags, 0, NULL, 0, p, n, NULL);
}
static ssize_t send_socket(void *u, int fd, const void *p, size_t n, int flags) {
    if (flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL | MSG_ZEROCOPY)) return unsupported("send flags");
    return CALL(7, fd, flags, 0, p, n, NULL, 0, NULL);
}
static ssize_t vector(void *u, int fd, const struct iovec *v, int count, int writing, int flags) {
    if (count < 0 || count > 1024) return bad(EINVAL);
    struct iovec vectors[1024];
    if (memory(vectors, v, count * sizeof(*v), 0)) return -1;
    size_t total = 0;
    for (int i = 0; i < count; i++) {
        if (!writing && vectors[i].iov_len && !vectors[i].iov_base) return bad(EFAULT);
        if (vectors[i].iov_len > 65535 - total) return bad(EMSGSIZE);
        total += vectors[i].iov_len;
    }
    if (!writing) {
        if (flags & ~MSG_DONTWAIT) return unsupported("recv flags");
        // Rust owns copyout and commits stream bytes only after all vectors succeed.
        return CALL(20, fd, flags, 0, vectors, count * sizeof(*v), NULL, total, NULL);
    }
    if (flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL | MSG_ZEROCOPY)) return unsupported("send flags");
    // Snapshot only bounded descriptors here; the owner checks state before payload copy.
    return CALL(21, fd, flags, 0, vectors, count * sizeof(*v), NULL, total, NULL);
}
static ssize_t readv_socket(void *u, int fd, const struct iovec *v, int n) { return vector(u, fd, v, n, 0, 0); }
static ssize_t writev_socket(void *u, int fd, const struct iovec *v, int n) { return vector(u, fd, v, n, 1, 0); }
static int destination(void *u, int fd, const struct sockaddr *addr, socklen_t len) {
    if (!addr) return len ? bad(EFAULT) : 0;
    if (len < sizeof(struct sockaddr_in)) return bad(EINVAL);
    struct sockaddr_in requested;
    if (memory(&requested, addr, sizeof(requested), 0)) return -1;
    if (requested.sin_family != AF_INET) return unsupported("send destination family");
    // A connection-mode TCP send uses its established peer, not msg_name.
    return 0;
}
static int source(void *u, int fd, struct sockaddr *addr, socklen_t *len) {
    if (!addr) return 0;
    if (!len) return bad(EFAULT);
    struct sockaddr_in peer;
    if (CALL(16, fd, 0, 0, NULL, 0, &peer, sizeof(peer), NULL) < 0) return -1;
    socklen_t capacity;
    if (memory(&capacity, len, sizeof(capacity), 0)) return -1;
    size_t n = capacity < sizeof(peer) ? capacity : sizeof(peer);
    if (memory(&peer, addr, n, 1)) return -1;
    capacity = sizeof(peer);
    return memory(&capacity, len, sizeof(capacity), 1);
}
static ssize_t recvfrom_socket(void *u, int fd, void *p, size_t n, int flags, struct sockaddr *addr, socklen_t *len) {
    if (source(u, fd, addr, len)) return -1;
    return recv_socket(u, fd, p, n, flags);
}
static ssize_t sendto_socket(void *u, int fd, const void *p, size_t n, int flags, const struct sockaddr *addr, socklen_t len) {
    if (destination(u, fd, addr, len)) return -1;
    return send_socket(u, fd, p, n, flags);
}
static ssize_t sendmsg_socket(void *u, int fd, const struct msghdr *msg, int flags) {
    struct msghdr header;
    if (memory(&header, msg, sizeof(header), 0)) return -1;
    if (header.msg_controllen) return unsupported("sendmsg ancillary data");
    if (destination(u, fd, header.msg_name, header.msg_namelen)) return -1;
    if (header.msg_iovlen > 1024) return bad(EINVAL);
    return vector(u, fd, header.msg_iov, header.msg_iovlen, 1, flags);
}
static ssize_t recvmsg_socket(void *u, int fd, struct msghdr *msg, int flags) {
    struct msghdr header;
    if (memory(&header, msg, sizeof(header), 0)) return -1;
    if (flags & MSG_ERRQUEUE) {
        if (flags & ~(MSG_ERRQUEUE | MSG_DONTWAIT)) return unsupported("error queue recv flags");
        if (header.msg_iovlen > 1024) return bad(EINVAL);
        struct iovec vectors[1024];
        if (memory(vectors, header.msg_iov, header.msg_iovlen * sizeof(*vectors), 0)) return -1;
        // The owner copies control and metadata before committing the completion.
        return CALL(22, fd, flags, 0, &header, sizeof(header), msg, sizeof(header), NULL);
    }
    if (header.msg_controllen) return unsupported("recvmsg ancillary data");
    if (header.msg_iovlen > 1024) return bad(EINVAL);
    if (source(u, fd, header.msg_name, &header.msg_namelen)) return -1;
    header.msg_flags = 0; header.msg_controllen = 0;
    // Complete metadata copyout before a receive can consume stream bytes.
    if (memory(&header, msg, sizeof(header), 1)) return -1;
    return vector(u, fd, header.msg_iov, header.msg_iovlen, 0, flags);
}
static int fcntl_socket(void *u, int fd, int cmd, ...) {
    int arg = 0;
    if (cmd == F_SETFL || cmd == F_SETFD) { va_list ap; va_start(ap, cmd); arg = va_arg(ap, int); va_end(ap); }
    else if (cmd != F_GETFL && cmd != F_GETFD) return unsupported("fcntl command");
    return SIMPLE(10, fd, cmd, arg);
}
static int ioctl_socket(void *u, int fd, unsigned long request, ...) {
    if (request != SIOCINQ) return unsupported("ioctl request");
    va_list ap; va_start(ap, request); int *out = va_arg(ap, int *); va_end(ap);
    // Validate the fd/state before touching the caller's output, as Linux does.
    int value = SIMPLE(17, fd, 0, 0);
    if (value < 0) return -1;
    if (!out) return bad(EFAULT);
    memcpy(out, &value, sizeof(value)); return 0;
}
static int close_socket(void *u, int fd) { return SIMPLE(8, fd, 0, 0); }
static int shutdown_socket(void *u, int fd, int how) {
    return SIMPLE(9, fd, how, 0);
}
static int setopt(void *u, int fd, int level, int name, const void *p, socklen_t n) {
    if (!((level == SOL_SOCKET && (name == SO_REUSEADDR || name == SO_ZEROCOPY)) || (level == IPPROTO_TCP && (name == TCP_NODELAY || name == TCP_USER_TIMEOUT)) || (level == IPPROTO_IP && (name == IP_TOS || name == IP_MTU_DISCOVER)))) return unsupported("setsockopt option");
    if (!p) return bad(EFAULT);
    if (level == IPPROTO_IP ? (n != 1 && n != sizeof(int)) : n < sizeof(int)) return bad(EINVAL);
    int value = 0;
    if (memory(&value, p, n == 1 ? 1 : sizeof(value), 0)) return -1;
    int key = level == IPPROTO_IP ? (name == IP_TOS ? 6 : 7) : level == SOL_SOCKET ? (name == SO_ZEROCOPY ? 8 : 1) : name == TCP_NODELAY ? 2 : 5;
    return SIMPLE(11, fd, key, value);
}
static int metric_option(int level, int name) {
    if (level == IPPROTO_TCP && name == TCP_INFO) return 1;
    if (level == IPPROTO_TCP && name == TCP_CC_INFO) return 2;
    if (level == SOL_SOCKET && name == SO_MEMINFO) return 3;
    return 0;
}
static int metric_getopt(void *u, int host, int fd, int option, void *p, socklen_t *n) {
    if (!n) return bad(EFAULT);
    socklen_t capacity; memcpy(&capacity, n, sizeof(capacity));
    if (!p && capacity) return bad(EFAULT);
    // Entire pinned ABI is initialized in Rust, never copied from Rust padding.
    unsigned char data[280] = {0};
    size_t size = capacity < sizeof(data) ? capacity : sizeof(data);
    long long result = host ? ntcp_host_call(fd, option, data, size)
        : CALL(18, fd, option, 0, NULL, 0, data, size, NULL);
    if (result < 0) return -1;
    if (result) memcpy(p, data, result);
    capacity = result; memcpy(n, &capacity, sizeof(capacity));
    return 0;
}
int ntcp_getsockopt_host(int fd, int level, int name, void *p, socklen_t *n) {
    int option = metric_option(level, name);
    if (option) {
        int result = metric_getopt(NULL, 1, fd, option, p, n);
        if (result >= 0 || errno != ENOENT) return result;
    }
    return syscall(SYS_getsockopt, fd, level, name, p, n);
}
static int getopt_socket(void *u, int fd, int level, int name, void *p, socklen_t *n) {
    int option = metric_option(level, name);
    if (option) return metric_getopt(u, 0, fd, option, p, n);
    if (!((level == SOL_SOCKET && (name == SO_REUSEADDR || name == SO_ERROR || name == SO_TYPE || name == SO_ZEROCOPY)) || (level == IPPROTO_TCP && (name == TCP_NODELAY || name == TCP_USER_TIMEOUT)) || (level == IPPROTO_IP && (name == IP_TOS || name == IP_MTU_DISCOVER)))) return unsupported("getsockopt option (including TCP_INFO)");
    if (!p || !n) return bad(EFAULT);
    int key = level == IPPROTO_IP ? (name == IP_TOS ? 6 : 7) : level == IPPROTO_TCP ? (name == TCP_NODELAY ? 2 : 5) : name == SO_ZEROCOPY ? 8 : name == SO_REUSEADDR ? 1 : name == SO_ERROR ? 3 : 4;
    int value = SIMPLE(12, fd, key, 0);
    if (value < 0) return -1;
    if (name == SO_ZEROCOPY && level == SOL_SOCKET) {
        socklen_t capacity;
        if (memory(&capacity, n, sizeof(capacity), 0)) return -1;
        capacity = capacity < sizeof(value) ? capacity : sizeof(value);
        if (memory(&value, p, capacity, 1)) return -1;
        return memory(&capacity, n, sizeof(capacity), 1);
    }
    // Linux's IPv4 integer options return a byte for short, nonzero buffers.
    if (level == IPPROTO_IP && *n && *n < sizeof(value)) {
        unsigned char byte = value; memcpy(p, &byte, 1); *n = 1; return 0;
    }
    size_t size = *n < sizeof(value) ? *n : sizeof(value); memcpy(p, &value, size); *n = size; return 0;
}
static int poll_socket(void *u, struct pollfd *fds, nfds_t n, int timeout) {
    if (n > 128) return bad(EINVAL);
    return CALL(13, 0, timeout, 0, fds, n * sizeof(*fds), fds, n * sizeof(*fds), NULL);
}
static int net_send(void *u, const void *p, size_t n) { return CALL(14, 0, 0, 0, p, n, NULL, 0, NULL); }
static int net_receive(void *u, void *p, size_t *n, long long *time) {
    if (!n || !time) return bad(EFAULT);
    long long result = CALL(15, 0, 0, 0, NULL, 0, p, *n, time);
    if (result < 0) { *n = 0; return -1; } *n = result; return 0;
}
static int sleep_host(void *u, useconds_t n) { return usleep(n); }
static int time_host(void *u, struct timeval *tv, struct timezone *tz) { if (!tv) return bad(EFAULT); return gettimeofday(tv, tz); }
static int ep_create(void *u, int size) { return unsupported("epoll_create"); }
static int ep_ctl(void *u, int epfd, int op, int fd, struct epoll_event *ev) { return unsupported("epoll_ctl"); }
static int ep_wait(void *u, int epfd, struct epoll_event *ev, int max, int timeout) { return unsupported("epoll_wait"); }
static int pipe_stub(void *u, int fds[2]) { return unsupported("pipe"); }
static int splice_stub(void *u, int in, loff_t *inoff, int out, loff_t *outoff, size_t n, unsigned int flags) { return unsupported("splice"); }
void ntcp_fill(struct packetdrill_interface *p, void *u) {
    *p = (struct packetdrill_interface) {
        .userdata=u, .free=ntcp_free, .socket=sock, .bind=bind_socket, .listen=listen_socket, .accept=accept_socket, .connect=connect_socket,
        .read=read_socket, .readv=readv_socket, .recv=recv_socket, .recvfrom=recvfrom_socket, .recvmsg=recvmsg_socket,
        .write=write_socket, .writev=writev_socket, .send=send_socket, .sendto=sendto_socket, .sendmsg=sendmsg_socket,
        .fcntl=fcntl_socket, .ioctl=ioctl_socket, .close=close_socket, .shutdown=shutdown_socket, .getsockopt=getopt_socket, .setsockopt=setopt,
        .poll=poll_socket, .netdev_send=net_send, .netdev_receive=net_receive, .usleep=sleep_host, .gettimeofday=time_host,
        .epoll_create=ep_create, .epoll_ctl=ep_ctl, .epoll_wait=ep_wait, .pipe=pipe_stub, .splice=splice_stub
    };
}

// Exercised from Rust's unit tests against the same table installed in stock packetdrill.
#include <assert.h>
void ntcp_abi_check(void *u) {
    struct packetdrill_interface p;
    ntcp_fill(&p, u);
    assert(p.free && p.socket && p.bind && p.listen && p.accept && p.connect);
    assert(p.read && p.readv && p.recv && p.recvfrom && p.recvmsg);
    assert(p.write && p.writev && p.send && p.sendto && p.sendmsg);
    assert(p.fcntl && p.ioctl && p.close && p.shutdown && p.getsockopt && p.setsockopt && p.poll);
    assert(p.netdev_send && p.netdev_receive && p.usleep && p.gettimeofday);
    assert(p.epoll_create && p.epoll_ctl && p.epoll_wait && p.pipe && p.splice);
    assert(p.socket(u, AF_INET6, SOCK_STREAM, 0) == -1 && errno == ENOSYS);
    assert(p.ioctl(u, -1, 0) == -1 && errno == ENOSYS);
    assert(p.getsockopt(u, -1, IPPROTO_TCP, TCP_INFO, NULL, NULL) == -1 && errno == EFAULT);
    assert(p.epoll_create(u, 1) == -1 && errno == ENOSYS);
    assert(p.epoll_ctl(u, -1, 0, -1, NULL) == -1 && errno == ENOSYS);
    assert(p.epoll_wait(u, -1, NULL, 0, 0) == -1 && errno == ENOSYS);
    assert(p.pipe(u, NULL) == -1 && errno == ENOSYS);
    assert(p.splice(u, -1, NULL, -1, NULL, 0, 0) == -1 && errno == ENOSYS);
    assert(p.readv(u, -1, NULL, 1) == -1 && errno == EFAULT);
    assert(p.writev(u, -1, NULL, -1) == -1 && errno == EINVAL);
    struct iovec v = { .iov_base = NULL, .iov_len = 1 };
    assert(p.readv(u, -1, &v, 1) == -1 && errno == EFAULT);
    v.iov_base = &v; v.iov_len = 65536;
    assert(p.writev(u, -1, &v, 1) == -1 && errno == EMSGSIZE);
    assert(p.read(u, -1, NULL, 1) == -1 && errno == EFAULT);
    assert(p.write(u, -1, NULL, 1) == -1 && errno == EBADF);
    assert(p.bind(u, -1, NULL, 0) == -1 && errno == EFAULT);
    assert(p.accept(u, -1, (struct sockaddr *)&v, NULL) == -1 && errno == EFAULT);
    assert(p.sendmsg(u, -1, NULL, 0) == -1 && errno == EFAULT);
    assert(p.recvmsg(u, -1, NULL, 0) == -1 && errno == EFAULT);
    assert(p.netdev_receive(u, NULL, NULL, NULL) == -1 && errno == EFAULT);
    assert(p.poll(u, NULL, 1, 0) == -1 && errno == EFAULT);
    int fd = p.socket(u, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(fd >= 0);
    int domain = 0; socklen_t domain_size = sizeof(domain);
    assert(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_size) == 0 && domain == AF_UNIX);
    assert(p.fcntl(u, fd, F_GETFL) == O_RDWR);
    assert(p.fcntl(u, fd, F_SETFL, O_RDWR | O_NONBLOCK) == 0);
    assert(p.fcntl(u, fd, F_GETFL) == (O_RDWR | O_NONBLOCK));
    int queued = -1;
    assert(p.ioctl(u, -1, SIOCINQ, &queued) == -1 && errno == EBADF && queued == -1);
    assert(p.ioctl(u, fd, SIOCINQ, NULL) == -1 && errno == EFAULT);
    assert(p.ioctl(u, fd, SIOCINQ, &queued) == 0 && queued == 0);
    int value = -1; socklen_t size = sizeof(value);
    assert(p.getsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, &size) == 0 && value == 0 && size == sizeof(value));
    value = 1234;
    assert(p.setsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, NULL, size) == -1 && errno == EFAULT);
    assert(p.setsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, 3) == -1 && errno == EINVAL);
    value = -1;
    assert(p.setsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, size) == -1 && errno == EINVAL);
    value = 1234;
    assert(p.setsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, size) == 0);
    value = 0;
    assert(p.getsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, &size) == 0 && value == 1234 && size == sizeof(value));
    assert(p.getsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, NULL, &size) == -1 && errno == EFAULT);
    assert(p.getsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, NULL) == -1 && errno == EFAULT);
    value = 0;
    assert(p.setsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, sizeof(value)) == 0);
    assert(p.getsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, &size) == 0 && value == 0);
    size = 1; unsigned char byte = 0;
    assert(p.getsockopt(u, fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &byte, &size) == 0 && size == 1 && byte == ((unsigned char *)&value)[0]);
    for (int option = 0; option < 2; option++) {
        int name = option ? IP_MTU_DISCOVER : IP_TOS;
        int expected = option ? IP_PMTUDISC_WANT : 0;
        size = sizeof(value);
        assert(p.getsockopt(u, fd, SOL_IP, name, &value, &size) == 0 && value == expected && size == sizeof(value));
        assert(p.setsockopt(u, fd, SOL_IP, name, NULL, 1) == -1 && errno == EFAULT);
        for (socklen_t length = 0; length <= 5; length++) {
            if (length == 1 || length == sizeof(int)) continue;
            assert(p.setsockopt(u, fd, SOL_IP, name, &value, length) == -1 && errno == EINVAL);
        }
        assert(p.setsockopt(u, -1, SOL_IP, name, &value, sizeof(value)) == -1 && errno == EBADF);
        value = option ? IP_PMTUDISC_DONT : 7;
        assert(p.setsockopt(u, fd, SOL_IP, name, &value, sizeof(value)) == 0);
        expected = option ? IP_PMTUDISC_DONT : 4;
        size = sizeof(value);
        assert(p.getsockopt(u, fd, SOL_IP, name, &value, &size) == 0 && value == expected);
        byte = option ? IP_PMTUDISC_DO : 255;
        assert(p.setsockopt(u, fd, SOL_IP, name, &byte, 1) == 0);
        expected = option ? IP_PMTUDISC_DO : 252;
        size = sizeof(value);
        assert(p.getsockopt(u, fd, SOL_IP, name, &value, &size) == 0 && value == expected);
        byte = 0; size = 1;
        assert(p.getsockopt(u, fd, SOL_IP, name, &byte, &size) == 0 && size == 1 && byte == expected);
        unsigned char truncated[8];
        for (socklen_t length = 1; length < sizeof(int); length++) {
            memset(truncated, 0xa5, sizeof(truncated)); size = length;
            assert(p.getsockopt(u, fd, SOL_IP, name, truncated, &size) == 0 && size == 1 && truncated[0] == expected && truncated[1] == 0xa5);
        }
        memset(truncated, 0xa5, sizeof(truncated));
        size = 0;
        assert(p.getsockopt(u, fd, SOL_IP, name, truncated, &size) == 0 && size == 0 && truncated[0] == 0xa5);
        size = sizeof(truncated);
        assert(p.getsockopt(u, fd, SOL_IP, name, truncated, &size) == 0 && size == sizeof(int) && truncated[4] == 0xa5);
        assert(p.getsockopt(u, fd, SOL_IP, name, NULL, &size) == -1 && errno == EFAULT);
        assert(p.getsockopt(u, fd, SOL_IP, name, &value, NULL) == -1 && errno == EFAULT);
        size = sizeof(value);
        if (option) {
            for (int mode = -1; mode <= 6; mode++) {
                if (mode >= IP_PMTUDISC_DONT && mode <= IP_PMTUDISC_DO) continue;
                assert(p.setsockopt(u, fd, SOL_IP, name, &mode, sizeof(mode)) == -1 && errno == (mode >= 3 && mode <= 5 ? ENOSYS : EINVAL));
                assert(p.getsockopt(u, fd, SOL_IP, name, &value, &size) == 0 && value == expected);
            }
        } else {
            value = -1;
            assert(p.setsockopt(u, fd, SOL_IP, name, &value, sizeof(value)) == 0);
            assert(p.getsockopt(u, fd, SOL_IP, name, &value, &size) == 0 && value == 252);
            value = 256;
            assert(p.setsockopt(u, fd, SOL_IP, name, &value, sizeof(value)) == 0);
            assert(p.getsockopt(u, fd, SOL_IP, name, &value, &size) == 0 && value == 0);
        }
    }
    assert(p.close(u, fd) == 0);
    // Stock socket_close uses libc, not the plugin callback, for open sockets.
    fd = p.socket(u, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(fd >= 0);
    size = sizeof(value);
    assert(p.getsockopt(u, fd, SOL_IP, IP_TOS, &value, &size) == 0 && value == 0);
    assert(p.getsockopt(u, fd, SOL_IP, IP_MTU_DISCOVER, &value, &size) == 0 && value == IP_PMTUDISC_WANT);
    assert(close(fd) == 0);
    struct timeval tv;
    assert(p.gettimeofday(u, &tv, NULL) == 0 && tv.tv_sec > 1700000000);
    assert(p.usleep(u, 1) == 0);
}

#include <sys/mman.h>
// Connected socket has "abcdef" queued by the Rust test, no privileges needed.
void ntcp_abi_fault_check(void *u, int fd) {
    struct packetdrill_interface p;
    ntcp_fill(&p, u);
    size_t page = sysconf(_SC_PAGESIZE);
    unsigned char *mapping = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    assert(mprotect(mapping + page, page, PROT_NONE) == 0);
    void *badptr = mapping + page;
    unsigned char out[8] = {0};
    struct iovec v[2] = {{out, 3}, {badptr, 3}};
    struct msghdr msg = {.msg_iov = v, .msg_iovlen = 2};
    for (int i = 0; i < 3; i++) {
        void *ptr = i == 0 ? NULL : i == 1 ? badptr : mapping + page - 2;
        assert(p.write(u, fd, ptr, 6) == -1 && errno == EFAULT);
        assert(p.send(u, fd, ptr, 6, 0) == -1 && errno == EFAULT);
        assert(p.sendto(u, fd, ptr, 6, 0, NULL, 0) == -1 && errno == EFAULT);
        assert(p.read(u, fd, ptr, 6) == -1 && errno == EFAULT);
        assert(p.recv(u, fd, ptr, 6, 0) == -1 && errno == EFAULT);
        assert(p.recvfrom(u, fd, ptr, 6, 0, NULL, NULL) == -1 && errno == EFAULT);
    }
    assert(p.readv(u, fd, badptr, 1) == -1 && errno == EFAULT);
    assert(p.writev(u, fd, badptr, 1) == -1 && errno == EFAULT);
    assert(p.sendmsg(u, fd, badptr, 0) == -1 && errno == EFAULT);
    assert(p.recvmsg(u, fd, badptr, 0) == -1 && errno == EFAULT);
    assert(p.readv(u, fd, v, 2) == -1 && errno == EFAULT);
    assert(p.writev(u, fd, v, 2) == -1 && errno == EFAULT);
    assert(p.sendmsg(u, fd, &msg, 0) == -1 && errno == EFAULT);
    assert(p.recvmsg(u, fd, &msg, 0) == -1 && errno == EFAULT);
    assert(p.readv(u, fd, v, 1025) == -1 && errno == EINVAL);
    assert(p.read(u, fd, badptr, 0) == 0);
    assert(p.write(u, fd, badptr, 0) == 0);
    socklen_t address_len = sizeof(struct sockaddr_in);
    assert(p.recvfrom(u, fd, out, 6, 0, badptr, &address_len) == -1 && errno == EFAULT);
    struct sockaddr_in address;
    assert(p.recvfrom(u, fd, out, 6, 0, (struct sockaddr *)&address, badptr) == -1 && errno == EFAULT);
    memcpy(mapping, &msg, sizeof(msg));
    assert(mprotect(mapping, page, PROT_READ) == 0);
    assert(p.read(u, fd, mapping, 6) == -1 && errno == EFAULT);
    assert(p.recvmsg(u, fd, (struct msghdr *)mapping, 0) == -1 && errno == EFAULT);
    int queued = -1;
    assert(p.ioctl(u, fd, SIOCINQ, &queued) == 0 && queued == 6);
    v[1].iov_base = out + 3;
    assert(p.recvmsg(u, fd, &msg, 0) == 6);
    assert(memcmp(out, "abcdef", 6) == 0);
    assert(p.ioctl(u, fd, SIOCINQ, &queued) == 0 && queued == 0);
    assert(p.recv(u, fd, badptr, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    assert(munmap(mapping, page * 2) == 0);
}

// Exercise every send entry point with readable descriptors and inaccessible payload.
void ntcp_abi_send_error_check(void *u, int fd, int first_error) {
    struct packetdrill_interface p;
    ntcp_fill(&p, u);
    size_t page = sysconf(_SC_PAGESIZE);
    void *payload = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(payload != MAP_FAILED);
    struct iovec v = {payload, 6};
    struct msghdr msg = {.msg_iov = &v, .msg_iovlen = 1};
    assert(p.write(u, fd, payload, 6) == -1 && errno == first_error);
    assert(p.send(u, fd, payload, 6, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    assert(p.sendto(u, fd, payload, 6, 0, NULL, 0) == -1 && errno == EPIPE);
    assert(p.writev(u, fd, &v, 1) == -1 && errno == EPIPE);
    assert(p.sendmsg(u, fd, &msg, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    v.iov_base = NULL;
    assert(p.write(u, fd, NULL, 6) == -1 && errno == EPIPE);
    assert(p.send(u, fd, NULL, 6, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    assert(p.sendto(u, fd, NULL, 6, 0, NULL, 0) == -1 && errno == EPIPE);
    assert(p.writev(u, fd, &v, 1) == -1 && errno == EPIPE);
    assert(p.sendmsg(u, fd, &msg, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    assert(munmap(payload, page) == 0);
}

// Native ABI copied-fallback contract, connected peer never ACKs these bytes.
void ntcp_abi_zerocopy_check(void *u, int fd) {
    struct packetdrill_interface p;
    ntcp_fill(&p, u);
    int value = -1; socklen_t size = sizeof(value);
    assert(p.getsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, &value, &size) == 0 && value == 0);
    unsigned char control[64];
    struct msghdr msg = {.msg_control = control, .msg_controllen = sizeof(control)};
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    assert(p.send(u, fd, "x", 1, MSG_ZEROCOPY) == 1); // Disabled: ordinary copy, no ID.
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    for (value = -1; value <= 2; value++) {
        int result = p.setsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, &value, sizeof(value));
        assert(result == (value < 0 || value > 1 ? -1 : 0));
        if (result < 0) assert(errno == EINVAL);
    }
    value = 1;
    assert(p.setsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, &value, 3) == -1 && errno == EINVAL);
    assert(p.setsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, (void *)1, 4) == -1 && errno == EFAULT);
    assert(p.getsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, &value, &size) == 0 && value == 1);
    assert(p.send(u, fd, "x", 1, MSG_MORE) == -1 && errno == ENOSYS);
    struct iovec v[4] = {{(void *)1, 0}, {NULL, 0}, {(void *)1, 0}, {NULL, 0}};
    struct msghdr send = {.msg_iov = v, .msg_iovlen = 4};
    assert(p.sendmsg(u, fd, &send, MSG_MORE) == -1 && errno == ENOSYS);
    assert(p.send(u, fd, "ordinary", 8, 0) == 8);
    assert(p.send(u, fd, (void *)1, 0, MSG_ZEROCOPY) == 0);
    assert(p.sendmsg(u, fd, &send, MSG_ZEROCOPY) == 0);
    send.msg_iovlen = 0;
    assert(p.sendmsg(u, fd, &send, MSG_ZEROCOPY) == 0);
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    send.msg_iovlen = 4; v[1] = (struct iovec){"abc", 3}; v[3] = (struct iovec){"de", 2};
    assert(p.sendmsg(u, fd, &send, MSG_ZEROCOPY | MSG_NOSIGNAL) == 5);
    assert(p.sendto(u, fd, "de", 2, MSG_ZEROCOPY, NULL, 0) == 2);
    v[1].iov_base = (void *)1;
    assert(p.sendmsg(u, fd, &send, MSG_ZEROCOPY) == -1 && errno == EFAULT);
    assert(p.send(u, fd, (void *)1, 3, MSG_ZEROCOPY) == -1 && errno == EFAULT);
    value = 0;
    assert(p.setsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, &value, 4) == 0);
    assert(p.send(u, fd, "f", 1, MSG_ZEROCOPY) == 1);
    struct pollfd pollfd = {.fd = fd, .events = 0};
    assert(p.poll(u, &pollfd, 1, 0) == 1 && pollfd.revents == POLLERR);
    int error = -1; size = sizeof(error);
    assert(p.getsockopt(u, fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0);
    msg.msg_control = (void *)1;
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == -1 && errno == EFAULT);
    size_t page = sysconf(_SC_PAGESIZE);
    void *readonly = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(readonly != MAP_FAILED);
    msg.msg_control = control; memcpy(readonly, &msg, sizeof(msg));
    assert(mprotect(readonly, page, PROT_READ) == 0);
    assert(p.recvmsg(u, fd, readonly, MSG_ERRQUEUE) == -1 && errno == EFAULT);
    assert(munmap(readonly, page) == 0);
    assert(p.poll(u, &pollfd, 1, 0) == 1 && pollfd.revents == POLLERR);
    memset(control, 0xa5, sizeof(control));
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == 0);
    assert(msg.msg_flags == MSG_ERRQUEUE && msg.msg_controllen == CMSG_SPACE(32) && msg.msg_namelen == 0);
    struct cmsghdr *c = (void *)control;
    assert(c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR && c->cmsg_len == CMSG_LEN(32));
    struct sock_extended_err *e = (void *)CMSG_DATA(c);
    assert(e->ee_errno == 0 && e->ee_origin == SO_EE_ORIGIN_ZEROCOPY && e->ee_code == SO_EE_CODE_ZEROCOPY_COPIED);
    assert(e->ee_info == 0 && e->ee_data == 1);
    for (size_t i = CMSG_LEN(16); i < CMSG_LEN(32); i++) assert(control[i] == 0);
    assert(control[CMSG_SPACE(32)] == 0xa5);
    assert(p.poll(u, &pollfd, 1, 0) == 0 && pollfd.revents == 0);
    value = 1; assert(p.setsockopt(u, fd, SOL_SOCKET, SO_ZEROCOPY, &value, 4) == 0);
    // Tiny and partial control buffers consume one completion, signal CTRUNC.
    size_t lengths[] = {0, sizeof(struct cmsghdr) - 1, sizeof(struct cmsghdr), CMSG_LEN(16), CMSG_LEN(32) - 1};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); i++) {
        assert(p.send(u, fd, "g", 1, MSG_ZEROCOPY) == 1);
        memset(control, 0xa5, sizeof(control));
        msg = (struct msghdr){.msg_control = control, .msg_controllen = lengths[i]};
        assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT) == 0);
        assert(msg.msg_flags == (MSG_ERRQUEUE | MSG_CTRUNC));
        assert(msg.msg_controllen == (lengths[i] < sizeof(*c) ? 0 : lengths[i]));
        if (lengths[i] >= sizeof(*c)) assert(c->cmsg_len == lengths[i]);
        assert(control[msg.msg_controllen] == 0xa5);
        assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
    }
    unsigned char *large = calloc(65535, 1); assert(large);
    ssize_t sent = p.send(u, fd, large, 65535, MSG_ZEROCOPY | MSG_DONTWAIT);
    assert(sent > 0 && sent < 65535); // Real partial write, one completion ID.
    assert(p.send(u, fd, large, 1, MSG_ZEROCOPY | MSG_DONTWAIT) == -1 && errno == EAGAIN);
    free(large);
    msg = (struct msghdr){.msg_control = control, .msg_controllen = sizeof(control)};
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == 0);
    assert(e->ee_info == 7 && e->ee_data == 7);
    assert(p.recvmsg(u, fd, &msg, MSG_ERRQUEUE) == -1 && errno == EAGAIN);
}
