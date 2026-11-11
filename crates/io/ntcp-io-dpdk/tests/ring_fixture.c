#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <rte_errno.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
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
    char mapping[64], prefix[64];
    snprintf(mapping, sizeof(mapping), "--lcores=0@%d", cpu);
    snprintf(prefix, sizeof(prefix), "--file-prefix=ntcp-ring-%d", (int)getpid());
    char *args[] = {"ntcp-test", mapping, "--no-huge", "--no-pci", "--in-memory",
                    prefix, "--no-telemetry", "-m", "64"};
    if (rte_eal_init(RTE_DIM(args), args) < 0) return -2;
    rx = rte_ring_create("ntcp_rx", 32, SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
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
        rte_eth_rx_queue_setup(port, 0, 32, SOCKET_ID_ANY, NULL, pool) ||
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
void ntcp_test_register_timestamp(void) {
    int offset;
    uint64_t flag;
    assert(rte_mbuf_dyn_rx_timestamp_register(&offset, &flag) == 0);
    int again;
    uint64_t again_flag;
    assert(rte_mbuf_dyn_rx_timestamp_register(&again, &again_flag) == 0);
    assert(again == offset && again_flag == flag);
}
void ntcp_test_timestamp(uint64_t value, int valid, int corrupt) {
    int offset = rte_mbuf_dynfield_lookup(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
    int bit = rte_mbuf_dynflag_lookup(RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL);
    assert(offset >= 0 && bit >= 0);
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    assert(m);
    void *bytes = rte_pktmbuf_append(m, 64);
    assert(bytes);
    memset(bytes, 0x42, 64);
    *RTE_MBUF_DYNFIELD(m, offset, rte_mbuf_timestamp_t *) = value;
    // Deliberately leave a stale field value when flag is absent.
    m->ol_flags = valid ? UINT64_C(1) << bit : 0;
    if (corrupt) m->pkt_len = 63;
    assert(rte_ring_enqueue(rx, m) == 0);
}
unsigned ntcp_test_tx_count(void) { return rte_ring_count(tx); }
unsigned ntcp_test_rx_count(void) { return rte_ring_count(rx); }
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

// Deterministic mbuf encoding evidence only: the ring PMD never schedules.
void ntcp_test_register_tx_timestamp(void) {
    int offset;
    uint64_t flag;
    assert(rte_mbuf_dyn_tx_timestamp_register(&offset, &flag) == 0);
}
void ntcp_test_check_scheduled(uint64_t value, unsigned length) {
    int offset = rte_mbuf_dynfield_lookup(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
    int bit = rte_mbuf_dynflag_lookup(RTE_MBUF_DYNFLAG_TX_TIMESTAMP_NAME, NULL);
    assert(offset >= 0 && bit >= 0);
    struct rte_mbuf *m;
    assert(rte_ring_dequeue(tx, (void **)&m) == 0);
    assert(m->ol_flags == (UINT64_C(1) << bit));
    assert(*RTE_MBUF_DYNFIELD(m, offset, rte_mbuf_timestamp_t *) == value);
    assert(m->pkt_len == length);
    for (struct rte_mbuf *s = m; s; s = s->next) {
        if (s != m) assert(s->ol_flags == 0);
        const unsigned char *bytes = rte_pktmbuf_mtod(s, const unsigned char *);
        for (unsigned i = 0; i < s->data_len; ++i) assert(bytes[i] == 7);
    }
    rte_pktmbuf_free(m);
}

// Read-only independent observation of the real borrowed ring port.
int ntcp_test_mtu(uint16_t port) {
    uint16_t mtu;
    int result = rte_eth_dev_get_mtu(port, &mtu);
    return result < 0 ? result : mtu;
}
int ntcp_test_emsgsize(void) { return EMSGSIZE; }

#include <rte_ip.h>
#include <rte_tcp.h>
extern int ntcp_dpdk_tso_gate(uint64_t, uint64_t, uint64_t, uint16_t, uint16_t, uint16_t, uint16_t *);
void ntcp_test_tso_gate(void) {
    const uint64_t req = RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
        RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    uint16_t limit = 0;
    assert(ntcp_dpdk_tso_gate(req, req, 0, 8, 4, 16, &limit) == 0 && limit == 1);
    uint64_t multi = req | RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    assert(ntcp_dpdk_tso_gate(multi, 0, multi, 8, 4, 16, &limit) == 0 && limit == 4);
    for (unsigned i = 0; i < 64; ++i) {
        uint64_t bit = UINT64_C(1) << i;
        if (!(req & bit)) continue;
        assert(ntcp_dpdk_tso_gate(req & ~bit, req, 0, 8, 4, 16, &limit) == -ENOTSUP);
        assert(ntcp_dpdk_tso_gate(req, req & ~bit, 0, 8, 4, 16, &limit) == -ENOTSUP);
    }
    assert(ntcp_dpdk_tso_gate(multi, multi, 0, 0, 4, 16, &limit) == -ENOTSUP);
    assert(ntcp_dpdk_tso_gate(multi, multi, 0, 8, 0, 16, &limit) == -ENOTSUP);
    assert(ntcp_dpdk_tso_gate(multi, multi, 0, 8, 4, 0, &limit) == -ENOTSUP);
}
void ntcp_test_check_tso(unsigned l3, unsigned l4, unsigned mss, unsigned length) {
    struct rte_mbuf *m;
    assert(rte_ring_dequeue(tx, (void **)&m) == 0);
    assert(m->pkt_len == length && m->l2_len == 14 && m->l3_len == l3);
    assert(m->l4_len == l4 && m->tso_segsz == mss);
    uint64_t expected = RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM |
        (l3 == 20 ? RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM : RTE_MBUF_F_TX_IPV6);
    assert(m->ol_flags == expected);
    struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, 14 + l3);
    uint16_t seed;
    // Independently zero pseudo-header length (the SDK helper omits it for TSO).
    if (l3 == 20) {
        struct rte_ipv4_hdr ip = *rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, 14);
        assert(ip.hdr_checksum == 0);
        ip.total_length = rte_cpu_to_be_16(20);
        seed = rte_ipv4_phdr_cksum(&ip, 0);
    } else {
        struct rte_ipv6_hdr ip = *rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *, 14);
        ip.payload_len = 0;
        seed = rte_ipv6_phdr_cksum(&ip, 0);
    }
    assert(tcp->cksum == seed);
    unsigned bytes = 0, segments = 0;
    for (struct rte_mbuf *s = m; s; s = s->next) {
        if (s != m) assert(s->ol_flags == 0);
        bytes += s->data_len; segments++;
    }
    assert(bytes == length && segments == m->nb_segs);
    rte_pktmbuf_free(m);
}

// Inspect the original external payload addresses, then perform actual mbuf
// reclamation. This is ownership/pointer evidence, not physical NIC evidence.
void ntcp_test_check_shared(const void *first, unsigned first_len,
                            const void *second, unsigned second_len,
                            unsigned header_length, unsigned total_length) {
    struct rte_mbuf *m;
    assert(rte_ring_dequeue(tx, (void **)&m) == 0);
    assert(m->pkt_len == (total_length < 60 ? 60 : total_length));
    assert(m->data_len == header_length);
    struct rte_mbuf *s = m->next;
    assert(s && (s->ol_flags & RTE_MBUF_F_EXTERNAL));
    assert(rte_pktmbuf_mtod(s, const void *) == first && s->data_len == first_len);
    if (second_len) {
        s = s->next;
        assert(s && (s->ol_flags & RTE_MBUF_F_EXTERNAL));
        assert(rte_pktmbuf_mtod(s, const void *) == second && s->data_len == second_len);
    }
    s = s->next;
    if (total_length < 60) {
        assert(s && s->data_len == 60 - total_length);
        const uint8_t *pad = rte_pktmbuf_mtod(s, const uint8_t *);
        for (unsigned i = 0; i < s->data_len; ++i) assert(pad[i] == 0);
        s = s->next;
    }
    assert(!s);
    rte_pktmbuf_free(m);
}
