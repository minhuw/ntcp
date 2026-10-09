// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void transfer(int fd, unsigned char *data, size_t size, int sending) {
    for (size_t offset = 0; offset < size;) {
        ssize_t n = sending ? send(fd, data + offset, size - offset, MSG_NOSIGNAL)
                            : recv(fd, data + offset, size - offset, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        offset += (size_t)n;
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--invalid")) {
        assert(socket(AF_INET, SOCK_STREAM, 0) == -1 && errno == EINVAL);
        return 0;
    }
    int server = argc > 1 && !strcmp(argv[1], "--server");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(16417)};
    assert(inet_pton(AF_INET, "10.73.0.1", &address.sin_addr) == 1);
    if (server) {
        int one = 1;
        assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
        assert(listen(fd, 4) == 0);
        puts("READY");
        fflush(stdout);
        int client = accept(fd, NULL, NULL);
        assert(client >= 0);
        assert(close(fd) == 0);
        fd = client;
    } else {
        assert(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    }
    struct timeval timeout = {.tv_sec = 10};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    unsigned char expected[150000], received[150000];
    for (int round = 0; round < 2; ++round) {
        for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (i + round) % 251;
        if (server) {
            transfer(fd, received, sizeof(received), 0);
            assert(!memcmp(expected, received, sizeof(expected)));
            transfer(fd, received, sizeof(received), 1);
        } else {
            transfer(fd, expected, sizeof(expected), 1);
            transfer(fd, received, sizeof(received), 0);
            assert(!memcmp(expected, received, sizeof(expected)));
            // Live idle smoke only; deterministic pacing tests use core deadlines.
            if (!round) usleep(20000);
        }
    }
    assert(shutdown(fd, SHUT_WR) == 0);
    assert(recv(fd, received, 1, 0) == 0);
    assert(close(fd) == 0);
    return 0;
}
