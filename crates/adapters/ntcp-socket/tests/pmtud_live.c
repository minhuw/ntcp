// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void transfer(int fd, unsigned char *data, size_t size, int sending) {
    for (size_t offset = 0; offset < size;) {
        ssize_t n = sending ? send(fd, data + offset, size - offset, MSG_NOSIGNAL)
                            : recv(fd, data + offset, size - offset, 0);
        assert(n > 0);
        offset += (size_t)n;
    }
}
int main(int argc, char **argv) {
    assert(argc == 3);
    int server = !strcmp(argv[1], "server"), ethernet = !strcmp(argv[2], "af-packet");
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(16419)};
    assert(inet_pton(AF_INET, "10.73.0.1", &addr.sin_addr) == 1);
    int listener = -1;
    if (server) {
        listener = socket(AF_INET, SOCK_STREAM, 0);
        assert(listener >= 0);
        assert(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        assert(listen(listener, 4) == 0);
        puts("READY"); fflush(stdout);
    }
    for (int round = 0; round < 2; ++round) {
        int fd = server ? accept(listener, NULL, NULL) : socket(AF_INET, SOCK_STREAM, 0);
        assert(fd >= 0);
        if (!server) assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        struct timeval timeout = {.tv_sec = 10};
        assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        assert(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        if (!server && !round) {
            int mtu = 0; socklen_t len = sizeof(mtu);
            assert(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len) == 0 && mtu == 1500);
            puts("CONNECTED"); fflush(stdout);
            assert(getchar() == 'x'); // Harness lowers the real link after handshake.
        }
        unsigned char expected[120000], received[120000];
        for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (i + round) % 251;
        if (server) {
            transfer(fd, received, sizeof(received), 0);
            assert(!memcmp(expected, received, sizeof(expected)));
            transfer(fd, received, sizeof(received), 1);
        } else {
            transfer(fd, expected, sizeof(expected), 1);
            transfer(fd, received, sizeof(received), 0);
            assert(!memcmp(expected, received, sizeof(expected)));
        }
        int mtu = 0; socklen_t len = sizeof(mtu);
        assert(getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len) == 0);
        // TUN writes inject IP into the kernel and need not reject at link MTU.
        if (ethernet) assert(mtu == 600);
        printf("%s round=%d mtu=%d\n", argv[1], round, mtu); fflush(stdout);
        assert(shutdown(fd, SHUT_WR) == 0);
        assert(recv(fd, received, 1, 0) == 0);
        assert(close(fd) == 0);
    }
    if (server) assert(close(listener) == 0);
    return 0;
}
