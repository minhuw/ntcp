// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "packetdrill.h"
#include "../../crates/adapters/ntcp-socket/src/boundary.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>
static int bad(int error) { errno = error; return -1; }
extern void ntcp_free(void *);
extern int ntcp_plugin_active(void *);
extern int ntcp_net_send(void *, const void *, size_t);
extern int ntcp_net_receive(void *, void *, size_t *, long long *);
extern int ntcp_net_send_segmented_impl(void *, const void *, size_t, uint16_t);
int ntcp_c_packet_net_send_segmented(void *u,const void *p,size_t n,uint16_t size) {
    return NTCP_RUST_CALL(int, ntcp_net_send_segmented_impl(u,p,n,size));
}
static int unsupported(const char *why) {
    fprintf(stderr, "NTCP_PACKETDRILL_UNSUPPORTED: %s\n", why);
    errno = ENOSYS; return -1;
}
extern int ntcp_c_packet_socket(int domain, int type, int protocol);
static int sock(void *u, int domain, int type, int protocol) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    if ((domain != AF_INET && domain != AF_INET6) || (type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != SOCK_STREAM || (protocol && protocol != IPPROTO_TCP)) return unsupported("socket: only IP TCP");
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
static int pipe_host(void *u, int fds[2]) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    return pipe(fds);
}
extern ssize_t ntcp_c_splice(int, loff_t *, int, loff_t *, size_t, unsigned int);
static int splice_socket(void *u, int in, loff_t *inoff, int out, loff_t *outoff, size_t n, unsigned int flags) {
    if (!NTCP_RUST_CALL(int, ntcp_plugin_active(u))) return -1;
    // Stock packetdrill passes addresses of numeric zero for script NULL.
    return ntcp_c_splice(in, inoff && *inoff ? inoff : NULL,
                         out, outoff && *outoff ? outoff : NULL, n, flags);
}
void ntcp_fill(struct packetdrill_interface *p, void *u) {
    *p = (struct packetdrill_interface) {
        .userdata=u, .free=ntcp_free, .socket=sock, .bind=bind_socket, .listen=listen_socket, .accept=accept_socket, .connect=connect_socket,
        .read=read_socket, .readv=readv_socket, .recv=recv_socket, .recvfrom=recvfrom_socket, .recvmsg=recvmsg_socket,
        .write=write_socket, .writev=writev_socket, .send=send_socket, .sendto=sendto_socket, .sendmsg=sendmsg_socket,
        .fcntl=fcntl_socket, .ioctl=ioctl_socket, .close=close_socket, .shutdown=shutdown_socket, .getsockopt=getopt_socket, .setsockopt=setopt,
        .poll=poll_socket, .netdev_send=net_send, .netdev_receive=net_receive, .usleep=sleep_host, .gettimeofday=time_host,
        .epoll_create=ep_create, .epoll_ctl=ep_ctl, .epoll_wait=ep_wait, .pipe=pipe_host, .splice=splice_socket
    };
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
