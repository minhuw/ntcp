#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
extern ssize_t __read_chk(int, void *, size_t, size_t);
extern ssize_t __recv_chk(int, void *, size_t, size_t, int);
extern ssize_t __recvfrom_chk(int, void *, size_t, size_t, int, struct sockaddr *, socklen_t *);
extern int __poll_chk(struct pollfd *, nfds_t, int, size_t);
extern int __ppoll_chk(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t);
static int fd, epfd, cleaned;
static atomic_int entered;
static const char *operation;
static void cleanup(void *p) { ++*(int *)p; }
static void *worker(void *unused) {
    (void)unused;
    char byte = 0;
    struct iovec v = {&byte, 1};
    struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
    struct pollfd p = {.fd = fd, .events = POLLIN};
    struct epoll_event event;
    fd_set set;
    FD_ZERO(&set); FD_SET(fd, &set);
    pthread_cleanup_push(cleanup, &cleaned);
    atomic_store(&entered, 1);
    if (!strcmp(operation, "close") || !strcmp(operation, "connect"))
        assert(!pthread_cancel(pthread_self()));
#define OP(name, call) if (!strcmp(operation, name)) { ssize_t result = (call); (void)result; } else
    OP("close", close(fd))
    OP("connect", connect(fd, NULL, 0))
    OP("pipe_read", read(fd, &byte, 1))
    OP("pipe_write", write(fd, &byte, 1))
    OP("read", read(fd, &byte, 1))
    OP("write", write(fd, &byte, 1))
    OP("readv", readv(fd, &v, 1))
    OP("writev", writev(fd, &v, 1))
    OP("recv", recv(fd, &byte, 1, 0))
    OP("send", send(fd, &byte, 1, 0))
    OP("recvfrom", recvfrom(fd, &byte, 1, 0, NULL, NULL))
    OP("sendto", sendto(fd, &byte, 1, 0, NULL, 0))
    OP("recvmsg", recvmsg(fd, &m, 0))
    OP("sendmsg", sendmsg(fd, &m, 0))
    OP("poll", poll(&p, 1, -1))
    OP("ppoll", ppoll(&p, 1, NULL, NULL))
    OP("select", select(fd + 1, &set, NULL, NULL, NULL))
    OP("pselect", pselect(fd + 1, &set, NULL, NULL, NULL, NULL))
    OP("epoll_wait", epoll_wait(epfd, &event, 1, -1))
    OP("epoll_pwait", epoll_pwait(epfd, &event, 1, -1, NULL))
    OP("epoll_pwait2", epoll_pwait2(epfd, &event, 1, NULL, NULL))
    OP("accept", accept(fd, NULL, NULL))
    OP("accept4", accept4(fd, NULL, NULL, 0))
    OP("__read_chk", __read_chk(fd, &byte, 1, 1))
    OP("__recv_chk", __recv_chk(fd, &byte, 1, 1, 0))
    OP("__recvfrom_chk", __recvfrom_chk(fd, &byte, 1, 1, 0, NULL, NULL))
    OP("__poll_chk", __poll_chk(&p, 1, -1, sizeof(p)))
    OP("__ppoll_chk", __ppoll_chk(&p, 1, NULL, NULL, sizeof(p)))
    { assert(!"unknown operation"); }
#undef OP
    pthread_cleanup_pop(0);
    return NULL; // A blocked call must cancel, not return normally.
}
#ifdef NTCP_EARLY
#define main ntcp_early_suite
#endif
int main(int argc, char **argv) {
    int managed = -1;
    if (argc > 1) { // Keep the configured registry populated during native calls.
        assert(!strcmp(argv[1], "--coexist"));
        managed = socket(AF_INET, SOCK_STREAM, 0);
        assert(managed >= 0);
    }
    const char *ops[] = {"close", "connect", "pipe_read", "pipe_write", "read", "write", "readv", "writev", "recv", "send",
        "recvfrom", "sendto", "recvmsg", "sendmsg", "poll", "ppoll", "select",
        "pselect", "epoll_wait", "epoll_pwait", "epoll_pwait2", "accept", "accept4",
        "__read_chk", "__recv_chk", "__recvfrom_chk", "__poll_chk", "__ppoll_chk"};
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); ++i) {
        operation = ops[i];
        int pair[2];
        int is_pipe = !strncmp(operation, "pipe_", 5);
        if (is_pipe) {
            assert(pipe(pair) == 0);
            if (strstr(operation, "write")) {
                int tmp = pair[0]; pair[0] = pair[1]; pair[1] = tmp;
            }
        } else assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        fd = pair[0];
        if (strstr(operation, "write") || !strncmp(operation, "send", 4)) {
            char bytes[4096] = {0};
            if (is_pipe) {
                assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
                while (syscall(SYS_write, fd, bytes, sizeof(bytes)) > 0) {}
                assert(errno == EAGAIN);
                assert(fcntl(fd, F_SETFL, 0) == 0);
            } else {
                while (syscall(SYS_sendto, fd, bytes, sizeof(bytes), MSG_DONTWAIT, NULL, 0) > 0) {}
                assert(errno == EAGAIN);
            }
        }
        if (!strncmp(operation, "accept", 6)) {
            close(fd);
            fd = socket(AF_UNIX, SOCK_STREAM, 0);
            assert(fd >= 0);
            struct sockaddr_un addr = {.sun_family = AF_UNIX};
            snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "ntcp-cancel-%d", getpid());
            assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
            assert(listen(fd, 1) == 0);
        }
        epfd = epoll_create1(EPOLL_CLOEXEC);
        assert(epfd >= 0);
        struct epoll_event event = {.events = EPOLLIN};
        assert(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0);
        entered = 0; cleaned = 0;
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, worker, NULL));
        while (!atomic_load(&entered)) sched_yield();
        usleep(20000);
        if (strcmp(operation, "close") && strcmp(operation, "connect"))
            assert(!pthread_cancel(thread));
        void *result;
        assert(!pthread_join(thread, &result));
        assert(result == PTHREAD_CANCELED && cleaned == 1);
        // A canceled native C close must release the mutation reader, or a
        // subsequent managed replacement spins forever (suite timeout).
        if (managed >= 0 && !strcmp(operation, "close")) {
            int target = dup(pair[1]);
            assert(target >= 0);
            assert(dup2(managed, target) == target);
            assert(close(target) == 0);
        }
        close(fd); close(pair[1]); close(epfd);
        printf("PASS cancel %s\n", operation);
    }
    if (managed >= 0) assert(close(managed) == 0);
    return 0;
}

#ifdef NTCP_EARLY
__attribute__((constructor)) static void early_preload_constructor(void) {
    char *args[] = {"early", NULL};
    assert(main(1, args) == 0);
    int native = open("/dev/null", O_RDWR);
    assert(native >= 0);
    FILE *stream = fdopen(native, "r+");
    assert(stream && fileno(stream) == native && fileno_unlocked(stream) == native);
    assert(fclose(stream) == 0);
}
#endif
