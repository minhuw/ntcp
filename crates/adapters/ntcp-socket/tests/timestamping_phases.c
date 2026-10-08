// SPDX-License-Identifier: GPL-2.0-or-later
// Reuse the nine-byte echo peer; this client requests real TX completions.
#define main ack_only_main
#include "timestamping.c"
#undef main
#include <sys/epoll.h>

int main(int argc, char **argv) {
    if (argc > 1) return ack_only_main(argc, argv);
    int fd = socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(16380)};
    assert(inet_pton(AF_INET, "10.73.0.1", &addr.sin_addr) == 1);
    assert(connect(fd, (void *)&addr, sizeof(addr)) == 0);
    int flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SCHED |
        SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_ACK |
        SOF_TIMESTAMPING_OPT_ID | SOF_TIMESTAMPING_OPT_TSONLY;
    assert(setsockopt(fd, SOL_SOCKET, 65, &flags, sizeof(flags)) == 0);
    int alias = dup(fd); assert(alias >= 0);
    int ep = epoll_create1(0); assert(ep >= 0);
    struct epoll_event event = {.events=0, .data.fd=alias};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, alias, &event) == 0);
    struct pollfd ready = {.fd=alias, .events=0};
    assert(poll(&ready, 1, 0) == 0);
    char data[] = "timestamp";
    assert(write(fd, data, 4) == 4);
    // Per-send requests must retain all three phases, not just core ACK.
    unsigned char control[CMSG_SPACE(sizeof(uint32_t))] = {0};
    struct iovec iov = {.iov_base=data+4, .iov_len=5};
    struct msghdr send = {.msg_iov=&iov, .msg_iovlen=1,
        .msg_control=control, .msg_controllen=sizeof(control)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&send);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=65; c->cmsg_len=CMSG_LEN(4);
    uint32_t generation = SOF_TIMESTAMPING_TX_SCHED |
        SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_ACK;
    memcpy(CMSG_DATA(c), &generation, sizeof(generation));
    assert(sendmsg(alias, &send, 0) == 5);
    assert(close(fd) == 0); // Pending records survive original descriptor close.
    void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(bad != MAP_FAILED);
    uint64_t stamps[2][3] = {{0}};
    for (int n=0; n<6; ++n) {
        assert(poll(&ready, 1, 3000) == 1 && (ready.revents & POLLERR));
        assert(epoll_wait(ep, &event, 1, 3000) == 1);
        assert(event.data.fd == alias && (event.events & EPOLLERR));
        struct msghdr msg = {.msg_control=bad, .msg_controllen=128};
        assert(recvmsg(alias, &msg, MSG_ERRQUEUE|MSG_DONTWAIT) == -1 && errno == EFAULT);
        assert(poll(&ready, 1, 0) == 1 && (ready.revents & POLLERR));
        unsigned char out[128] = {0};
        msg.msg_control=out; msg.msg_controllen=sizeof(out);
        assert(recvmsg(alias, &msg, MSG_ERRQUEUE|MSG_DONTWAIT) == 0);
        assert(msg.msg_flags == MSG_ERRQUEUE);
        c=CMSG_FIRSTHDR(&msg);
        assert(c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == 65);
        assert(c->cmsg_len == CMSG_LEN(48));
        struct timespec ts[3]; memcpy(ts, CMSG_DATA(c), sizeof(ts));
        assert(ts[0].tv_sec > 0 && ts[0].tv_nsec >= 0 && ts[0].tv_nsec < 1000000000);
        assert(!ts[1].tv_sec && !ts[1].tv_nsec && !ts[2].tv_sec && !ts[2].tv_nsec);
        c=CMSG_NXTHDR(&msg, c);
        assert(c && c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR);
        assert(c->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err)));
        struct sock_extended_err ee; memcpy(&ee, CMSG_DATA(c), sizeof(ee));
        assert(ee.ee_errno == ENOMSG && ee.ee_origin == SO_EE_ORIGIN_TIMESTAMPING);
        assert(!ee.ee_type && !ee.ee_code && !ee.ee_pad);
        assert(ee.ee_info <= 2 && (ee.ee_data == 3 || ee.ee_data == 8));
        unsigned id = ee.ee_data == 3 ? 0 : 1;
        assert(stamps[id][ee.ee_info] == 0); // No duplicates or cross-write IDs.
        stamps[id][ee.ee_info] = (uint64_t)ts[0].tv_sec*1000000000 + ts[0].tv_nsec;
        printf("TX id=%u phase=%u ns=%llu\n", ee.ee_data, ee.ee_info,
               (unsigned long long)stamps[id][ee.ee_info]); fflush(stdout);
        assert(CMSG_NXTHDR(&msg, c) == NULL);
    }
    for (int id=0; id<2; ++id) {
        assert(stamps[id][SCM_TSTAMP_SCHED] > 0);
        assert(stamps[id][SCM_TSTAMP_SCHED] <= stamps[id][SCM_TSTAMP_SND]);
        assert(stamps[id][SCM_TSTAMP_SND] <= stamps[id][SCM_TSTAMP_ACK]);
    }
    struct msghdr empty = {0};
    assert(recvmsg(alias, &empty, MSG_ERRQUEUE|MSG_DONTWAIT) == -1 && errno == EAGAIN);
    assert(poll(&ready, 1, 100) == 0);
    assert(epoll_wait(ep, &event, 1, 0) == 0);
    int error=-1; socklen_t len=sizeof(error);
    assert(getsockopt(alias, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0);
    char received[9]; size_t n=0;
    while (n<sizeof(received)) {
        ssize_t r=read(alias, received+n, sizeof(received)-n); assert(r>0); n+=(size_t)r;
    }
    assert(memcmp(received, data, sizeof(received)) == 0);
    assert(shutdown(alias, SHUT_WR) == 0);
    assert(read(alias, received, 1) == 0);
    assert(munmap(bad, 4096) == 0);
    assert(close(ep) == 0 && close(alias) == 0);
    puts("PASS live TX SCHED/SND/ACK: two last-byte IDs, ordering, queue, poll/epoll, alias close, fault rollback");
}
