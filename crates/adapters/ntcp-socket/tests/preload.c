#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/ntcp-preload-XXXXXX", buffer[16] = {0};
    int file = mkstemp(path);
    assert(file >= 0);
    assert(unlink(path) == 0);
    assert(write(file, "file", 4) == 4);
    assert(lseek(file, 0, SEEK_SET) == 0);
    assert(read(file, buffer, sizeof(buffer)) == 4);
    assert(memcmp(buffer, "file", 4) == 0);
    int duplicate = fcntl(file, F_DUPFD_CLOEXEC, 0);
    assert(duplicate >= 0);
    assert(fcntl(duplicate, F_GETFD) & FD_CLOEXEC);
    assert(dup2(file, duplicate) == duplicate);
    assert((fcntl(duplicate, F_GETFD) & FD_CLOEXEC) == 0);
    assert(close(duplicate) == 0 && close(file) == 0);

    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    int flags = fcntl64(pair[0], F_GETFL);
    assert(flags >= 0);
    assert(fcntl64(pair[0], F_SETFL, flags | O_NONBLOCK) == 0);
    assert(read(pair[0], buffer, sizeof(buffer)) == -1 && errno == EAGAIN);
    struct iovec vectors[] = {{"ab", 2}, {"cd", 2}};
    assert(writev(pair[1], vectors, 2) == 4);
    int available = 0;
    assert(ioctl(pair[0], FIONREAD, &available) == 0 && available == 4);
    struct pollfd pollfd = {pair[0], POLLIN, 0};
    assert(poll(&pollfd, 1, 0) == 1 && (pollfd.revents & POLLIN));
    struct timespec zero = {0, 0};
    assert(ppoll(&pollfd, 1, &zero, NULL) == 1);
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pair[0], &readfds);
    struct timeval timeout = {0, 0};
    assert(select(pair[0] + 1, &readfds, NULL, NULL, &timeout) == 1);
    assert(FD_ISSET(pair[0], &readfds));
    FD_ZERO(&readfds);
    FD_SET(pair[0], &readfds);
    assert(pselect(pair[0] + 1, &readfds, NULL, NULL, &zero, NULL) == 1);

    int ep = epoll_create1(EPOLL_CLOEXEC);
    assert(ep >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET | EPOLLONESHOT};
    event.data.u64 = 0xfedcba9876543210ULL;
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, pair[0], &event) == 0);
    struct epoll_event result;
    assert(epoll_wait(ep, &result, 1, 100) == 1);
    assert((result.events & EPOLLIN) && result.data.u64 == event.data.u64);
    assert(epoll_wait(ep, &result, 1, 0) == 0);
    assert(epoll_ctl(ep, EPOLL_CTL_MOD, pair[0], &event) == 0);
    assert(epoll_pwait(ep, &result, 1, 100, NULL) == 1);
    assert(result.data.u64 == event.data.u64);
    assert(recv(pair[0], buffer, 4, MSG_PEEK) == 4);
    assert(memcmp(buffer, "abcd", 4) == 0);
    struct iovec receive[] = {{buffer, 1}, {buffer + 1, 3}};
    assert(readv(pair[0], receive, 2) == 4);
    assert(memcmp(buffer, "abcd", 4) == 0);
    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
    assert(sendmsg(pair[1], &message, MSG_NOSIGNAL) == 4);
    message.msg_iov = receive;
    assert(recvmsg(pair[0], &message, 0) == 4);
    assert(memcmp(buffer, "abcd", 4) == 0);
    assert(epoll_ctl(ep, EPOLL_CTL_DEL, pair[0], NULL) == 0);
    assert(close(ep) == 0);
    assert(shutdown(pair[1], SHUT_WR) == 0);
    assert(read(pair[0], buffer, sizeof(buffer)) == 0);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);

    int tcp = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(tcp >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(tcp, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(tcp, 1) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(tcp, (struct sockaddr *)&address, &length) == 0);
    assert(address.sin_port != 0);
    assert(close(tcp) == 0);
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    assert(udp >= 0);
    int type = 0;
    length = sizeof(type);
    assert(getsockopt(udp, SOL_SOCKET, SO_TYPE, &type, &length) == 0);
    assert(type == SOCK_DGRAM);
    assert(close(udp) == 0);

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        assert(write(pipefd[1], "x", 1) == 1);
        _exit(0);
    }
    assert(read(pipefd[0], buffer, 1) == 1 && buffer[0] == 'x');
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    return 0;
}
