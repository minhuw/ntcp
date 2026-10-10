// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define FLOWS 4
static pthread_barrier_t barrier;
struct flow { int fd, server; };
static void transfer(int fd, unsigned char *bytes, size_t len, int send_data) {
    for (size_t at = 0; at < len;) {
        ssize_t n = send_data ? send(fd, bytes + at, len - at, MSG_NOSIGNAL)
                             : recv(fd, bytes + at, len - at, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        at += (size_t)n;
    }
}
static void *exchange(void *argument) {
    struct flow *flow = argument;
    struct timeval timeout = {.tv_sec = 10};
    assert(setsockopt(flow->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(setsockopt(flow->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    pthread_barrier_wait(&barrier);
    unsigned char expected[150000], received[150000];
    for (unsigned round = 0; round < 2; ++round) {
        for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (i + round) % 251;
        if (flow->server) {
            transfer(flow->fd, received, sizeof(received), 0);
            assert(!memcmp(expected, received, sizeof(expected)));
            transfer(flow->fd, received, sizeof(received), 1);
        } else {
            transfer(flow->fd, expected, sizeof(expected), 1);
            transfer(flow->fd, received, sizeof(received), 0);
            assert(!memcmp(expected, received, sizeof(expected)));
            if (!round) usleep(20000);
        }
    }
    assert(shutdown(flow->fd, SHUT_WR) == 0);
    assert(recv(flow->fd, received, 1, 0) == 0);
    assert(close(flow->fd) == 0);
    return NULL;
}
int main(int argc, char **argv) {
    int server = argc > 1 && !strcmp(argv[1], "--server");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(16417)};
    assert(inet_pton(AF_INET, "10.73.0.1", &address.sin_addr) == 1);
    int listener = -1;
    if (server) {
        listener = socket(AF_INET, SOCK_STREAM, 0);
        assert(listener >= 0);
        int one = 1;
        assert(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
        assert(listen(listener, FLOWS) == 0);
        puts("READY");
        fflush(stdout);
    }
    assert(pthread_barrier_init(&barrier, NULL, FLOWS) == 0);
    pthread_t threads[FLOWS];
    struct flow flows[FLOWS];
    for (int i = 0; i < FLOWS; ++i) {
        int fd = server ? accept(listener, NULL, NULL) : socket(AF_INET, SOCK_STREAM, 0);
        assert(fd >= 0);
        if (!server) assert(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
        flows[i] = (struct flow){.fd = fd, .server = server};
        assert(pthread_create(&threads[i], NULL, exchange, &flows[i]) == 0);
    }
    for (int i = 0; i < FLOWS; ++i) assert(pthread_join(threads[i], NULL) == 0);
    if (server) assert(close(listener) == 0);
    assert(pthread_barrier_destroy(&barrier) == 0);
    return 0;
}
