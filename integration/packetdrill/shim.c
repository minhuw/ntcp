// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "packetdrill.h"
#include "../../crates/adapters/ntcp-socket/src/boundary.h"
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
static int bad(int error) { errno = error; return -1; }
extern void ntcp_free(void *);
extern int ntcp_plugin_active(void *);
extern int ntcp_net_send(void *, const void *, size_t);
extern int ntcp_net_receive(void *, void *, size_t *, long long *);
static int unsupported(const char *why) {
    fprintf(stderr, "NTCP_PACKETDRILL_UNSUPPORTED: %s\n", why);
    errno = ENOSYS; return -1;
}
extern int ntcp_c_packet_socket(int domain, int type, int protocol);
static int sock(void *u, int domain, int type, int protocol) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    if (domain != AF_INET || (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != SOCK_STREAM || (protocol && protocol != IPPROTO_TCP)) return unsupported("socket: only IPv4 TCP");
    return ntcp_c_packet_socket(domain,type,protocol);
}
extern int ntcp_c_bind(int fd, const struct sockaddr *p, socklen_t n);
static int bind_socket(void *u, int fd, const struct sockaddr *p, socklen_t n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_bind(fd,p,n);
}
extern int ntcp_c_connect(int fd, const struct sockaddr *p, socklen_t n);
static int connect_socket(void *u, int fd, const struct sockaddr *p, socklen_t n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_connect(fd,p,n);
}
extern int ntcp_c_listen(int fd, int n);
static int listen_socket(void *u, int fd, int n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_listen(fd,n);
}
extern int ntcp_c_accept(int fd, struct sockaddr *p, socklen_t *n);
static int accept_socket(void *u, int fd, struct sockaddr *p, socklen_t *n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_accept(fd,p,n);
}
extern ssize_t ntcp_c_read(int fd, void *p, size_t n);
static ssize_t read_socket(void *u, int fd, void *p, size_t n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_read(fd,p,n);
}
extern ssize_t ntcp_c_write(int fd, const void *p, size_t n);
static ssize_t write_socket(void *u, int fd, const void *p, size_t n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_write(fd,p,n);
}
extern ssize_t ntcp_c_send(int fd, const void *p, size_t n, int flags);
static ssize_t send_socket(void *u, int fd, const void *p, size_t n, int flags) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_send(fd,p,n,flags);
}
extern ssize_t ntcp_c_recv(int fd, void *p, size_t n, int flags);
static ssize_t recv_socket(void *u, int fd, void *p, size_t n, int flags) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_recv(fd,p,n,flags);
}
extern ssize_t ntcp_c_readv(int fd, const struct iovec *v, int n);
static ssize_t readv_socket(void *u, int fd, const struct iovec *v, int n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_readv(fd,v,n);
}
extern ssize_t ntcp_c_writev(int fd, const struct iovec *v, int n);
static ssize_t writev_socket(void *u, int fd, const struct iovec *v, int n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_writev(fd,v,n);
}
extern ssize_t ntcp_c_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *addr, socklen_t len);
static ssize_t sendto_socket(void *u, int fd, const void *p, size_t n, int flags, const struct sockaddr *addr, socklen_t len) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_sendto(fd,p,n,flags,addr,len);
}
extern ssize_t ntcp_c_recvfrom(int fd, void *p, size_t n, int flags, struct sockaddr *addr, socklen_t *len);
static ssize_t recvfrom_socket(void *u, int fd, void *p, size_t n, int flags, struct sockaddr *addr, socklen_t *len) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_recvfrom(fd,p,n,flags,addr,len);
}
extern ssize_t ntcp_c_sendmsg(int fd, const struct msghdr *msg, int flags);
static ssize_t sendmsg_socket(void *u, int fd, const struct msghdr *msg, int flags) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_sendmsg(fd,msg,flags);
}
extern ssize_t ntcp_c_recvmsg(int fd, struct msghdr *msg, int flags);
static ssize_t recvmsg_socket(void *u, int fd, struct msghdr *msg, int flags) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_recvmsg(fd,msg,flags);
}
extern int ntcp_c_close(int fd);
static int close_socket(void *u, int fd) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_close(fd);
}
extern int ntcp_c_shutdown(int fd, int how);
static int shutdown_socket(void *u, int fd, int how) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_shutdown(fd,how);
}
extern int ntcp_c_setsockopt(int fd, int level, int name, const void *p, socklen_t n);
static int setopt(void *u, int fd, int level, int name, const void *p, socklen_t n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_setsockopt(fd,level,name,p,n);
}
extern int ntcp_c_getsockopt(int fd, int level, int name, void *p, socklen_t *n);
static int getopt_socket(void *u, int fd, int level, int name, void *p, socklen_t *n) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_getsockopt(fd,level,name,p,n);
}
extern int ntcp_c_poll(struct pollfd *fds, nfds_t n, int timeout);
static int poll_socket(void *u, struct pollfd *fds, nfds_t n, int timeout) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return ntcp_c_poll(fds,n,timeout);
}
extern int ntcp_variadic_fcntl(int, int, ...);
extern int ntcp_variadic_ioctl(int, unsigned long, ...);
static int fcntl_socket(void *u, int fd, int cmd, ...) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    int arg = 0;
    if (cmd == F_SETFL || cmd == F_SETFD) { va_list ap; va_start(ap, cmd); arg = va_arg(ap, int); va_end(ap); }
    else if (cmd != F_GETFL && cmd != F_GETFD) return unsupported("fcntl command");
    return ntcp_variadic_fcntl(fd, cmd, arg);
}
static int ioctl_socket(void *u, int fd, unsigned long request, ...) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    if (request != SIOCINQ) return unsupported("ioctl request");
    va_list ap; va_start(ap, request); void *out = va_arg(ap, void *); va_end(ap);
    return ntcp_variadic_ioctl(fd, request, out);
}
static int net_send(void *u, const void *p, size_t n) { return NTCP_RUST_CALL(int, ntcp_net_send(u,p,n)); }
static int net_receive(void *u, void *p, size_t *n, long long *time) { return NTCP_RUST_CALL(int, ntcp_net_receive(u,p,n,time)); }
static int sleep_host(void *u, useconds_t n) { return usleep(n); }
static int time_host(void *u, struct timeval *tv, struct timezone *tz) { if (!tv) return bad(EFAULT); return gettimeofday(tv, tz); }
extern int ntcp_c_epoll_create(int);
extern int ntcp_c_epoll_ctl(int, int, int, struct epoll_event *);
extern int ntcp_c_epoll_wait(int, struct epoll_event *, int, int);
static int ep_create(void *u, int size) { if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1; return ntcp_c_epoll_create(size); }
static int ep_ctl(void *u, int epfd, int op, int fd, struct epoll_event *ev) { if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1; return ntcp_c_epoll_ctl(epfd,op,fd,ev); }
static int ep_wait(void *u, int epfd, struct epoll_event *ev, int max, int timeout) { if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1; return ntcp_c_epoll_wait(epfd,ev,max,timeout); }
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
    assert(p.getsockopt(u, -1, IPPROTO_TCP, TCP_INFO, NULL, NULL) == -1 && errno == EBADF);
    int epfd = p.epoll_create(u, 1); assert(epfd >= 0);
    struct epoll_event event = {.events = EPOLLIN};
    assert(p.epoll_ctl(u, epfd, EPOLL_CTL_ADD, -1, &event) == -1 && errno == EBADF);
    assert(p.epoll_wait(u, epfd, &event, 1, 0) == 0);
    assert(p.close(u, epfd) == 0);
    assert(p.pipe(u, NULL) == -1 && errno == ENOSYS);
    assert(p.splice(u, -1, NULL, -1, NULL, 0, 0) == -1 && errno == ENOSYS);
    assert(p.readv(u, -1, NULL, 1) == -1 && errno == EBADF);
    assert(p.writev(u, -1, NULL, -1) == -1 && errno == EBADF);
    struct iovec v = { .iov_base = NULL, .iov_len = 1 };
    assert(p.readv(u, -1, &v, 1) == -1 && errno == EBADF);
    v.iov_base = &v; v.iov_len = 65536;
    assert(p.writev(u, -1, &v, 1) == -1 && errno == EBADF);
    assert(p.read(u, -1, NULL, 1) == -1 && errno == EBADF);
    assert(p.write(u, -1, NULL, 1) == -1 && errno == EBADF);
    assert(p.bind(u, -1, NULL, 0) == -1 && errno == EBADF);
    assert(p.accept(u, -1, (struct sockaddr *)&v, NULL) == -1 && errno == EBADF);
    assert(p.sendmsg(u, -1, NULL, 0) == -1 && errno == EBADF);
    assert(p.recvmsg(u, -1, NULL, 0) == -1 && errno == EBADF);
    assert(p.netdev_receive(u, NULL, NULL, NULL) == -1 && errno == EFAULT);
    assert(p.poll(u, NULL, 1, 0) == -1 && errno == EFAULT);
    int fd = p.socket(u, AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(fd >= 0);
    int domain = 0; socklen_t domain_size = sizeof(domain);
    assert(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_size) == 0 && domain == AF_INET);
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

/* Loader/lifecycle calls also return from Rust before restoring cancellation. */
extern void ntcp_plugin_init(const char *, void *);
extern void ntcp_plugin_free(void *);
void ntcp_c_packet_init(const char *flags, void *interface) {
    (void)NTCP_RUST_CALL(int, (ntcp_plugin_init(flags, interface), 0));
}
void ntcp_c_packet_free(void *userdata) {
    (void)NTCP_RUST_CALL(int, (ntcp_plugin_free(userdata), 0));
}

// Actual callback-table coverage, including every ordinary receive entry point.
void ntcp_abi_receive_unsupported(void *u) {
    struct packetdrill_interface p; ntcp_fill(&p, u);
    int fd = p.socket(u, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    assert(fd >= 0);
    char bytes[65536];
    struct iovec v = {.iov_base = bytes, .iov_len = 1};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
    assert(p.recv(u, fd, bytes, 1, MSG_WAITALL) == -1 && errno == ENOSYS);
    assert(p.recvfrom(u, fd, bytes, 1, MSG_WAITALL, NULL, NULL) == -1 && errno == ENOSYS);
    assert(p.recvmsg(u, fd, &m, MSG_WAITALL) == -1 && errno == ENOSYS);
    assert(p.recv(u, fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == ENOSYS);
    assert(p.recvfrom(u, fd, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, NULL) == -1 && errno == ENOSYS);
    assert(p.read(u, fd, bytes, sizeof(bytes)) == -1 && errno == ENOSYS);
    v.iov_len = sizeof(bytes);
    assert(p.recvmsg(u, fd, &m, MSG_DONTWAIT) == -1 && errno == ENOSYS);
    assert(p.readv(u, fd, &v, 1) == -1 && errno == ENOSYS);
    assert(p.close(u, fd) == 0);
}
