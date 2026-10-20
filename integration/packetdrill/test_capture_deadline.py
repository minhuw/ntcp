import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from run import runner_provenance


class CaptureDeadlineChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get('PACKETDRILL_PATCHED_RUNNER')
        if not value or not shutil.which('cc'):
            raise unittest.SkipTest('audited patched runner and C compiler required')
        cls.runner = Path(value).resolve()
        runner_provenance(cls.runner)
        cls.source = cls.runner.parent
        cls.temp = tempfile.TemporaryDirectory(prefix='ntcp-capture-check-')
        cls.root = Path(cls.temp.name)
        (cls.root / 'capture.c').write_text(UNIT_SOURCE)
        subprocess.run(['cc', '-Wall', '-Werror',
                        '-ffunction-sections', '-fdata-sections',
                        '-I', str(cls.source), str(cls.root / 'capture.c'),
                        '-Wl,--gc-sections', '-o', str(cls.root / 'capture')], check=True)
        (cls.root / 'fake.c').write_text(PLUGIN_SOURCE)
        cls.plugin = cls.root / 'fake.so'
        subprocess.run(['cc', '-D_GNU_SOURCE', '-shared', '-fPIC', '-Wall', '-Werror',
                        '-I', str(cls.source), str(cls.root / 'fake.c'),
                        '-o', str(cls.plugin)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_receive_deadlines_errors_cleanup_and_unbounded_semantics(self):
        subprocess.run([str(self.root / 'capture')], check=True, timeout=8)

    def replay(self, mode, size, when=0):
        script = self.root / (mode + '.pkt')
        connect = ('+0...0.1 connect(3, ..., ...) = -1 ETIMEDOUT (Connection timed out)\n'
                   if mode == 'worker' else
                   '+0 connect(3, ..., ...) = -1 EINPROGRESS (Operation now in progress)\n')
        script.write_text('0 socket(..., SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP) = 3\n'
                          + connect + f'+{when} > S 0:{size}({size}) win 1000\n')
        started = time.monotonic()
        result = subprocess.run([str(self.runner), f'--so_filename={self.plugin}',
                                 f'--so_flags={mode}', '--ip_version=ipv4',
                                 '--local_ip=192.0.2.1', '--remote_ip=192.0.2.2',
                                 '--connect_port=8080', '--tolerance_usecs=1000000',
                                 str(script)], capture_output=True, text=True, timeout=9,
                                env={k: v for k, v in os.environ.items() if k != 'LD_PRELOAD'})
        return result, time.monotonic() - started

    def test_entire_aggregation_deadline_including_continuous_partial_packets(self):
        for mode in ['empty', 'zero', 'partial', 'unknown']:
            with self.subTest(mode=mode):
                result, elapsed = self.replay(mode, 60000)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('outbound capture timed out', result.stderr)
                self.assertGreaterEqual(elapsed, 1.8)
                self.assertLess(elapsed, 4.5)

    def test_completed_syscall_worker_cannot_hide_capture_timeout(self):
        result, elapsed = self.replay('worker', 100)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fake syscall returned ETIMEDOUT', result.stderr)
        self.assertIn('outbound capture timed out', result.stderr)
        self.assertLess(elapsed, 4.5)

    def test_fatal_callback_error_is_reported(self):
        result, elapsed = self.replay('fatal', 100)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('netdev_receive failed', result.stderr)
        self.assertIn('errno 5', result.stderr)
        self.assertLess(elapsed, 2)

    def test_matching_fragments_complete_and_future_event_keeps_its_budget(self):
        for mode, size, when in [('enough', 200, 0), ('future', 100, 3)]:
            with self.subTest(mode=mode):
                result, elapsed = self.replay(mode, size, when)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if when:
                    self.assertGreaterEqual(elapsed, 2.9)


# Compile the production receive implementation with a fake callback/parser. This
# checks timeout return codes and ownership without depending on host networking.
UNIT_SOURCE = r'''
#include "so_testing.c"
#include <stdarg.h>
void die(char *format, ...) {
    va_list ap; va_start(ap, format); vfprintf(stderr, format, ap); va_end(ap); exit(1);
}
static int allocated, calls, mode;
struct packet *packet_new(u32 size) {
    struct packet *p = calloc(1, sizeof(*p));
    p->buffer = malloc(size); p->buffer_bytes = size; ++allocated; return p;
}
void packet_free(struct packet *p) {
    if (p) { free(p->buffer); free(p); --allocated; }
}
int parse_packet(struct packet *p, int bytes, enum packet_layer_t layer, char **error) {
    (void)p; (void)bytes; (void)layer;
    if (mode == 4) { asprintf(error, "unknown"); return PACKET_UNKNOWN_L4; }
    if (mode == 5) { asprintf(error, "bad"); return PACKET_BAD; }
    return PACKET_OK;
}
static int capture(void *u, void *buf, size_t *n, long long *stamp) {
    (void)u; (void)buf; ++calls; *stamp = 123456789;
    if (mode == 1) { errno = EAGAIN; return -1; }
    if (mode == 2) { errno = EIO; return -1; }
    if (mode == 3 || mode == 4 || mode == 5 || (mode == 6 && calls > 2)) { *n = 1; return 0; }
    *n = 0; return 0;
}
static void check(struct so_netdev *dev, int kind, int expected) {
    mode = kind; calls = 0; struct packet *p = NULL; char *error = NULL;
    dev->receive_deadline = receive_now() + 15000;
    s64 start = receive_now();
    int result = so_netdev_receive(&dev->netdev, 1, &p, &error);
    assert(result == expected);
    assert(receive_now() - start < 500000);
    if (expected == STATUS_OK) assert(p && p->time_usecs == 123456789);
    else assert(p == NULL);
    if (kind == 2) assert(error && strstr(error, "errno 5") && errno == EIO);
    packet_free(p); free(error); assert(allocated == 0);
}
int main(void) {
    struct packetdrill_interface ifc = {.netdev_receive = capture};
    struct so_netdev dev = {.ifc = &ifc};
    check(&dev, 0, STATUS_TIMEOUT); check(&dev, 1, STATUS_TIMEOUT);
    check(&dev, 2, STATUS_ERR); check(&dev, 3, STATUS_OK);
    check(&dev, 4, STATUS_TIMEOUT); check(&dev, 5, STATUS_ERR);
    for (int timeout = -1; timeout <= 0; ++timeout) {
        char *error = NULL; struct packet *p = NULL; mode = 6; calls = 0;
        assert(!so_netdev_begin_receive(&dev.netdev, timeout, &error));
        assert(!dev.receive_deadline);
        assert(so_netdev_receive(&dev.netdev, timeout, &p, &error) == STATUS_OK);
        assert(calls == 3); packet_free(p); assert(!allocated); free(error);
        so_netdev_end_receive(&dev.netdev); assert(!dev.receive_deadline);
    }
    return 0;
}
'''

# Real runner event/aggregation path, no shell setup or real TCP connection. All
# syscalls are callbacks; only temporary local socket allocation belongs to runner.
PLUGIN_SOURCE = r'''
#include "packetdrill.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static const char *mode;
static struct timespec start;
static int count;
static double age(void) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec - start.tv_sec + (now.tv_nsec - start.tv_nsec) / 1e9;
}
static int sock(void *u, int d, int t, int p) { (void)u; return socket(d, t, p); }
static int conn(void *u, int s, const struct sockaddr *a, socklen_t n) {
    (void)u; (void)s; (void)a; (void)n;
    if (!strcmp(mode, "worker")) {
        usleep(100000); fprintf(stderr, "fake syscall returned ETIMEDOUT\n");
        errno = ETIMEDOUT; return -1;
    }
    errno = EINPROGRESS; return -1;
}
static void release(void *u) { (void)u; }
static int cls(void *u, int fd) { (void)u; return close(fd); }
static int inject(void *u, const void *p, size_t n) { (void)u; (void)p; (void)n; return 0; }
static int tv(void *u, struct timeval *t, struct timezone *z) { (void)u; return gettimeofday(t, z); }
static int pause_us(void *u, useconds_t n) { (void)u; return usleep(n); }
static unsigned short checksum(const void *v, size_t n) {
    const unsigned short *p = v; unsigned sum = 0;
    while (n > 1) { sum += *p++; n -= 2; }
    if (n) sum += *(const unsigned char *)p;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return ~sum;
}
static int capture(void *u, void *buf, size_t *n, long long *stamp) {
    (void)u;
    if (!strcmp(mode, "fatal")) { errno = EIO; return -1; }
    if (!strcmp(mode, "empty") || !strcmp(mode, "worker")) { *n = 0; return 0; }
    if (!strcmp(mode, "future") && age() < 3) { *n = 0; return 0; }
    if (!strcmp(mode, "enough") && count >= 2) { *n = 0; return 0; }
    if (!strcmp(mode, "unknown")) {
        memset(buf, 0, 20); struct iphdr *ip = buf; ip->version = 4;
        ip->ihl = 5; ip->tot_len = htons(20); ip->protocol = 253;
        ip->check = checksum(ip, 20); *n = 20; return 0;
    }
    int size = !strcmp(mode, "zero") ? 0 : 100;
    memset(buf, 0, 40 + size);
    struct iphdr *ip = buf; ip->version = 4; ip->ihl = 5;
    ip->tot_len = htons(40 + size); ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.0.2.1"); ip->daddr = inet_addr("192.0.2.2");
    ip->check = checksum(ip, 20);
    struct tcphdr *tcp = (void *)((char *)buf + 20);
    tcp->source = htons(40000); tcp->dest = htons(8080); tcp->doff = 5;
    tcp->syn = 1; tcp->window = htons(1000); tcp->seq = htonl(count * size);
    unsigned char pseudo[12 + 20 + 100] = {0};
    memcpy(pseudo, &ip->saddr, 8); pseudo[9] = 6;
    unsigned short len = htons(20 + size); memcpy(pseudo + 10, &len, 2);
    memcpy(pseudo + 12, tcp, 20 + size); tcp->check = checksum(pseudo, 32 + size);
    struct timeval now; gettimeofday(&now, NULL); *stamp = (long long)now.tv_sec * 1000000 + now.tv_usec;
    *n = 40 + size; ++count;
    if (!strcmp(mode, "partial") || !strcmp(mode, "zero")) usleep(20000);
    return 0;
}
void packetdrill_interface_init(const char *flags, struct packetdrill_interface *p) {
    mode = strdup(flags); clock_gettime(CLOCK_MONOTONIC, &start); count = 0;
    memset(p, 0, sizeof(*p)); p->socket = sock; p->connect = conn; p->close = cls;
    p->netdev_receive = capture; p->netdev_send = inject;
    p->gettimeofday = tv; p->usleep = pause_us; p->free = release;
}
'''
