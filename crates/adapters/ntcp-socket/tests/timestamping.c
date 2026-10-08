// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1],"--invalid")==0) {
        assert(socket(AF_INET,SOCK_STREAM,0)==-1 && errno==EINVAL);
        return 0;
    }
    if (argc > 1) {
        int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
        struct sockaddr_in bindaddr={.sin_family=AF_INET,.sin_port=htons(16380)};
        assert(bind(listener,(void*)&bindaddr,sizeof(bindaddr))==0);
        assert(listen(listener,1)==0);
        puts("READY");fflush(stdout);
        int peer=accept(listener,NULL,NULL);assert(peer>=0);
        char bytes[9];size_t n=0;
        while(n<9) {ssize_t r=read(peer,bytes+n,9-n);assert(r>0);n+=(size_t)r;}
        assert(write(peer,bytes,9)==9);
        assert(shutdown(peer,SHUT_WR)==0);
        assert(read(peer,bytes,1)==0);
        assert(close(peer)==0 && close(listener)==0);
        return 0;
    }
    int fd=socket(AF_INET,SOCK_STREAM,0); assert(fd>=0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(16380)};
    assert(inet_pton(AF_INET,"10.73.0.1",&addr.sin_addr)==1);
    assert(connect(fd,(void*)&addr,sizeof(addr))==0);
    int flags=SOF_TIMESTAMPING_SOFTWARE|SOF_TIMESTAMPING_RX_SOFTWARE|
        SOF_TIMESTAMPING_TX_SCHED|SOF_TIMESTAMPING_TX_SOFTWARE|SOF_TIMESTAMPING_TX_ACK|
        SOF_TIMESTAMPING_OPT_ID|SOF_TIMESTAMPING_OPT_TSONLY;
    assert(setsockopt(fd,SOL_SOCKET,65,&flags,sizeof(flags))==0);
    int alias=dup(fd); assert(alias>=0);
    int value[2]={-1,-1}; socklen_t len=sizeof(value);
    assert(getsockopt(alias,SOL_SOCKET,65,value,&len)==0 && len==8 && value[0]==flags && value[1]==0);
    int invalid=1<<30;
    assert(setsockopt(fd,SOL_SOCKET,37,&invalid,4)==-1 && errno==EINVAL);
    unsigned char control[CMSG_SPACE(4)]={0};
    char data[]="timestamp";
    struct iovec iov={data,9};
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg); c->cmsg_level=SOL_SOCKET;c->cmsg_type=65;c->cmsg_len=CMSG_LEN(4);
    uint32_t generation=SOF_TIMESTAMPING_TX_ACK;
    memcpy(CMSG_DATA(c),&generation,4);
    assert(sendmsg(alias,&msg,0)==9);
    // Caller sends only ACK generation: no SCHED or SND record is permitted.
    struct pollfd pollfd={fd,POLLERR,0};
    assert(poll(&pollfd,1,3000)==1 && pollfd.revents&POLLERR);
    void *bad=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(bad!=MAP_FAILED);
    msg.msg_iov=NULL;msg.msg_iovlen=0;msg.msg_control=bad;msg.msg_controllen=128;
    assert(recvmsg(fd,&msg,MSG_ERRQUEUE)==-1 && errno==EFAULT);
    unsigned char out[128]={0};msg.msg_control=out;msg.msg_controllen=sizeof(out);
    assert(recvmsg(alias,&msg,MSG_ERRQUEUE)==0 && msg.msg_flags==MSG_ERRQUEUE);
    c=CMSG_FIRSTHDR(&msg);assert(c && c->cmsg_type==65 && c->cmsg_len==CMSG_LEN(48));
    struct timespec *ts=(void*)CMSG_DATA(c);assert(ts[0].tv_sec>0 && ts[1].tv_sec==0 && ts[2].tv_sec==0);
    c=CMSG_NXTHDR(&msg,c);assert(c && c->cmsg_level==SOL_IP && c->cmsg_type==IP_RECVERR);
    struct sock_extended_err *ee=(void*)CMSG_DATA(c);
    assert(ee->ee_errno==ENOMSG && ee->ee_origin==SO_EE_ORIGIN_TIMESTAMPING && ee->ee_info==2 && ee->ee_data==8);
    assert(recvmsg(fd,&msg,MSG_ERRQUEUE)==-1 && errno==EAGAIN);
    // Faulted RX ancillary copy leaves the same bytes/provenance for alias retry.
    char received[9];iov.iov_base=received;iov.iov_len=9;
    msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=bad;msg.msg_controllen=128;
    assert(recvmsg(fd,&msg,0)==-1 && errno==EFAULT);
    msg.msg_control=out;msg.msg_controllen=sizeof(out);
    assert(recvmsg(alias,&msg,MSG_PEEK)==9 && !memcmp(received,data,9));
    c=CMSG_FIRSTHDR(&msg);assert(c && c->cmsg_type==65);
    unsigned char stamp[48];memcpy(stamp,CMSG_DATA(c),48);
    msg.msg_controllen=sizeof(out);
    assert(recvmsg(fd,&msg,0)==9 && !memcmp(received,data,9));
    c=CMSG_FIRSTHDR(&msg);assert(c && !memcmp(stamp,CMSG_DATA(c),48));
    assert(munmap(bad,4096)==0);
    // Keep both owner threads alive through FIN delivery; process exit is not
    // a transport flush barrier for the userspace backend.
    assert(shutdown(fd,SHUT_WR)==0);
    assert(read(fd,received,1)==0);
    assert(close(alias)==0 && close(fd)==0);
    puts("PASS live timestamp ABI, per-send override, alias, RX PEEK/fault rollback");
}
