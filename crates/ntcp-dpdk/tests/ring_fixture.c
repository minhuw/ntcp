#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <rte_errno.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

static struct rte_ring *rx, *tx;
static struct rte_mempool *pool;
static struct rte_mbuf *held[1023];
static unsigned held_count;
static uint16_t port;

int ntcp_test_init(void) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus)) return -1;
    int cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &cpus); ++cpu) {}
    char mapping[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    char *args[] = {"ntcp-test", mapping, "--no-huge", "--no-pci",
                    "--no-shconf", "--no-telemetry", "-m", "64", "-d",
                    getenv("NTCP_DPDK_TEST_MEMPOOL_PMD")};
    int argc = args[9] ? 10 : 8;
    if (rte_eal_init(argc, args) < 0) return -2;
    rx = rte_ring_create("ntcp_rx", 8, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
    tx = rte_ring_create("ntcp_tx", 8, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
    pool = rte_pktmbuf_pool_create("ntcp_pool", 1023, 0, 0, 256, SOCKET_ID_ANY);
    if (!rx || !tx || !pool) {
        fprintf(stderr, "ring fixture allocation: %s\n", rte_strerror(rte_errno));
        return -3;
    }
    int id = rte_eth_from_rings("ntcp_ring", &rx, 1, &tx, 1, SOCKET_ID_ANY);
    if (id < 0) return -4;
    port = (uint16_t)id;
    struct rte_eth_conf conf = {0};
    if (rte_eth_dev_configure(port, 1, 1, &conf) ||
        rte_eth_rx_queue_setup(port, 0, 8, SOCKET_ID_ANY, NULL, pool) ||
        rte_eth_tx_queue_setup(port, 0, 8, SOCKET_ID_ANY, NULL) ||
        rte_eth_dev_start(port)) return -5;
    return port;
}
void *ntcp_test_pool(void) { return pool; }
unsigned ntcp_test_available(void) { return rte_mempool_avail_count(pool); }
unsigned ntcp_test_loopback(void) {
    struct rte_mbuf *m;
    assert(rte_ring_dequeue(tx, (void **)&m) == 0);
    for (struct rte_mbuf *s = m; s; s = s->next) assert(s->ol_flags == 0);
    unsigned segments = m->nb_segs;
    assert(rte_ring_enqueue(rx, m) == 0);
    return segments;
}
void ntcp_test_transformed(unsigned kind) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    assert(m);
    assert(rte_pktmbuf_append(m, 64));
    switch (kind) {
    case 0:
        m->ol_flags = RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
        m->vlan_tci = 42;
        break;
    case 1:
        // Outer-only stripping can leave the inner VLAN in the bytes.
        m->ol_flags = RTE_MBUF_F_RX_QINQ | RTE_MBUF_F_RX_QINQ_STRIPPED;
        m->vlan_tci_outer = 43;
        m->vlan_tci = 42;
        break;
    case 2:
        m->ol_flags = RTE_MBUF_F_RX_LRO;
        m->tso_segsz = 32;
        break;
    default: assert(0);
    }
    assert(rte_ring_enqueue(rx, m) == 0);
}
void ntcp_test_corrupt(void) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    assert(m);
    assert(rte_pktmbuf_append(m, 8));
    m->pkt_len = 7; // Valid allocation/chain, inconsistent packet metadata.
    assert(rte_ring_enqueue(rx, m) == 0);
}
void ntcp_test_hold(unsigned leave) {
    while (rte_mempool_avail_count(pool) > leave) {
        held[held_count] = rte_pktmbuf_alloc(pool);
        assert(held[held_count]);
        ++held_count;
    }
}
void ntcp_test_release(void) {
    while (held_count) rte_pktmbuf_free(held[--held_count]);
}
void ntcp_test_finish(void) {
    ntcp_test_release();
    struct rte_mbuf *m;
    while (rte_ring_dequeue(tx, (void **)&m) == 0) rte_pktmbuf_free(m);
    while (rte_ring_dequeue(rx, (void **)&m) == 0) rte_pktmbuf_free(m);
    assert(rte_mempool_avail_count(pool) == 1023);
    assert(rte_eth_dev_stop(port) == 0);
    assert(rte_eth_dev_close(port) == 0);
    rte_ring_free(rx);
    rte_ring_free(tx);
    rte_mempool_free(pool);
    assert(rte_eal_cleanup() == 0);
}
