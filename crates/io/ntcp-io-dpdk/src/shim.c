#define ALLOW_EXPERIMENTAL_API // rte_eth_dev_conf_get, rte_eth_read_clock.
#include "shim.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_mempool.h>
#include <rte_errno.h>

int ntcp_dpdk_get_mtu(uint16_t port, uint16_t *mtu) {
    return rte_eth_dev_get_mtu(port, mtu);
}

int ntcp_dpdk_valid_port(uint16_t port) {
    return rte_eth_dev_is_valid_port(port);
}

// Host/PMD registers the standard field/flag during setup. Look up once per
// adapter, never register or reconfigure a live device on the packet path.
static int timestamp_lookup(const char *name, int *offset, uint64_t *flag) {
    struct rte_mbuf_dynfield field;
    int off = rte_mbuf_dynfield_lookup(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, &field);
    if (off < 0) return -rte_errno;
    if (field.size != sizeof(rte_mbuf_timestamp_t) ||
        field.align != _Alignof(rte_mbuf_timestamp_t) || field.flags != 0)
        return -EINVAL;
    struct rte_mbuf_dynflag dynflag;
    int bit = rte_mbuf_dynflag_lookup(name, &dynflag);
    if (bit < 0) return -rte_errno;
    if (bit >= 64 || dynflag.flags != 0) return -EINVAL;
    *offset = off;
    *flag = UINT64_C(1) << bit;
    return 0;
}

int ntcp_dpdk_rx_timestamp_lookup(int *offset, uint64_t *flag) {
    return timestamp_lookup(RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, offset, flag);
}

int ntcp_dpdk_tx_timestamp_lookup(int *offset, uint64_t *flag) {
    return timestamp_lookup(RTE_MBUF_DYNFLAG_TX_TIMESTAMP_NAME, offset, flag);
}

int ntcp_dpdk_tx_scheduling_check(uint16_t port, uint16_t queue) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    if (queue >= info.nb_tx_queues) return -EINVAL;
    if (!(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP))
        return -ENOTSUP;
    // This reads actual host configuration, not a caller assertion. Port-wide
    // offloads apply to all TX queues. Never configure a borrowed port here.
    struct rte_eth_conf conf;
    result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    if (conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP) return 0;
    // Also accept a queue-only offload, but only with affirmative PMD evidence.
    struct rte_eth_txq_info qinfo;
    result = rte_eth_tx_queue_info_get(port, queue, &qinfo);
    if (result < 0) return result;
    return (qinfo.conf.offloads & RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP) ? 0 : -ENOTSUP;
}

int ntcp_dpdk_rx_timestamp_status(uint16_t port, uint16_t queue,
                                   int *supported, int *enabled) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    *supported = !!(info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP);
    // dev_conf_get is EXPERIMENTAL in 23.11; use the stable queue API.
    // Some PMDs do not implement it: unknown is not disabled or enabled.
    *enabled = -1;
    struct rte_eth_rxq_info qinfo;
    result = rte_eth_rx_queue_info_get(port, queue, &qinfo);
    if (result == -ENOTSUP) return 0;
    if (result < 0) return result;
    *enabled = !!(qinfo.conf.offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP);
    return 0;
}

void ntcp_dpdk_packet_free(void *packet) {
    rte_pktmbuf_free(packet);
}

void ntcp_dpdk_frame_free(void *packet) {
    // receive_check and direct_frame verified a direct mbuf with refcnt 1,
    // nb_segs 1 and next NULL. Only the frame owned it since then, and the
    // frame's cursors never modify the mbuf.
    rte_mbuf_raw_free(packet);
}

// Whether TCP checksum offload is enabled on RX queue `queue`: on the port
// (every queue), or on the queue itself when the PMD reports its
// configuration. Read-only; a borrowed port is never configured here.
int ntcp_dpdk_rx_checksum_check(uint16_t port, uint16_t queue) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    if (queue >= info.nb_rx_queues) return -EINVAL;
    if (!(info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)) return -ENOTSUP;
    struct rte_eth_conf conf;
    result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    if (conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) return 0;
    struct rte_eth_rxq_info qinfo;
    result = rte_eth_rx_queue_info_get(port, queue, &qinfo);
    if (result < 0) return result;
    return (qinfo.conf.offloads & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) ? 0 : -ENOTSUP;
}

enum { NTCP_L4_UNKNOWN, NTCP_L4_GOOD, NTCP_L4_BAD };

// 0 for an mbuf chain the adapter takes, else the negative errno it is
// refused with: transformed bytes, or a chain that is malformed or longer
// than `capacity`. Reads only; frees nothing.
static int receive_check(const struct rte_mbuf *m, size_t capacity) {
    // PacketIo carries bytes only: stripped tags and coalesced packets cannot
    // be reconstructed from offload metadata without changing its contract.
    if (m->ol_flags & (RTE_MBUF_F_RX_VLAN_STRIPPED |
                       RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_LRO))
        return -ENOTSUP;
    size_t total = m->pkt_len;
    if (total > NTCP_DPDK_MAX_PACKET_LEN || total > capacity)
        return -EMSGSIZE;
    // The usual packet is the head alone. Its packet and segment lengths
    // must agree, and the entire data range must belong to its buffer.
    if (m->nb_segs == 1) {
        if (m->next || m->data_len != total ||
            (uint32_t)m->data_off + m->data_len > m->buf_len)
            return -EIO;
        return 0;
    }
    // Validate the entire chain before any of its bytes are used.
    size_t sum = 0;
    const struct rte_mbuf *segment = m;
    for (uint32_t i = 0; i < m->nb_segs; ++i) {
        if (!segment || segment->data_off > segment->buf_len ||
            segment->data_len > segment->buf_len - segment->data_off ||
            segment->data_len > total - sum)
            return -EIO;
        sum += segment->data_len;
        segment = segment->next;
    }
    if (segment || !m->nb_segs || sum != total)
        return -EIO;
    return 0;
}

// A burst can describe direct pool frames while the mbuf headers the PMD
// just filled are hot. A null view requests the usual chain check at
// delivery. All mbufs, including ones that check will reject, stay owned
// by the adapter until it dequeues or drops them.
static inline int direct_frame(struct rte_mbuf *m, const void *pool) {
    return m->nb_segs == 1 && RTE_MBUF_DIRECT(m) && m->pool == pool &&
           rte_mbuf_refcnt_read(m) == 1;
}

uint16_t ntcp_dpdk_receive_burst(uint16_t port, uint16_t queue,
                                 struct rte_mbuf **packets, uint16_t count,
                                 const void *pool, int l4_checksum,
                                 struct ntcp_rx_view *views) {
    uint16_t received = rte_eth_rx_burst(port, queue, packets, count);
    if (views) {
        for (uint16_t i = 0; i < received; ++i) {
            struct rte_mbuf *m = packets[i];
            if (direct_frame(m, pool) && receive_check(m, NTCP_DPDK_MAX_PACKET_LEN) == 0) {
                views[i].data = rte_pktmbuf_mtod(m, void *);
                views[i].length = m->data_len;
                uint8_t l4_status = NTCP_L4_UNKNOWN;
                if (l4_checksum) {
                    switch (m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) {
                    case RTE_MBUF_F_RX_L4_CKSUM_GOOD: l4_status = NTCP_L4_GOOD; break;
                    case RTE_MBUF_F_RX_L4_CKSUM_BAD: l4_status = NTCP_L4_BAD; break;
                    default: break;
                    }
                }
                views[i].l4_status = l4_status;
            } else {
                views[i].data = NULL;
            }
        }
    }
    return received;
}

static void receive_metadata(const struct rte_mbuf *m, int timestamp_offset,
                             uint64_t timestamp_flag, uint64_t *timestamp,
                             int *timestamp_valid, int l4_checksum, int *l4_status) {
    *timestamp = 0;
    *timestamp_valid = 0;
    *l4_status = NTCP_L4_UNKNOWN;
    if (timestamp_offset >= 0 && (m->ol_flags & timestamp_flag)) {
        *timestamp = *RTE_MBUF_DYNFIELD(m, timestamp_offset, rte_mbuf_timestamp_t *);
        *timestamp_valid = 1;
    }
    // Meaningful only with RX TCP checksum offload enabled. NONE (the
    // packet's checksum field is not final, its data verified) stays
    // unknown: the stack verifies the field itself.
    if (l4_checksum) {
        switch (m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) {
        case RTE_MBUF_F_RX_L4_CKSUM_GOOD: *l4_status = NTCP_L4_GOOD; break;
        case RTE_MBUF_F_RX_L4_CKSUM_BAD: *l4_status = NTCP_L4_BAD; break;
        default: break;
        }
    }
}

int ntcp_dpdk_receive(void *packet, uint8_t *out,
                      size_t capacity, size_t *length, int timestamp_offset,
                      uint64_t timestamp_flag, uint64_t *timestamp, int *timestamp_valid,
                      int l4_checksum, int *l4_status) {
    struct rte_mbuf *m = packet;
    *length = 0;
    receive_metadata(m, -1, 0, timestamp, timestamp_valid, 0, l4_status);
    int result = receive_check(m, capacity);
    if (result == 0) {
        size_t offset = 0;
        for (struct rte_mbuf *segment = m; segment; segment = segment->next) {
            memcpy(out + offset, rte_pktmbuf_mtod(segment, const void *), segment->data_len);
            offset += segment->data_len;
        }
        receive_metadata(m, timestamp_offset, timestamp_flag, timestamp, timestamp_valid,
                         l4_checksum, l4_status);
        *length = m->pkt_len;
        result = 1;
    }
    // RX dequeue transferred this entire chain to us, even on rejection.
    rte_pktmbuf_free(m);
    return result;
}

// The receive of an mbuf the adapter may hand over by reference: 1 with
// its bytes (*data, *length) and metadata when it is one segment of
// `pool`'s own memory, uniquely held (direct, refcount 1), and kept by the
// caller; NTCP_DPDK_COPY, nothing consumed, for one the caller copies
// with ntcp_dpdk_receive instead (a scatter chain, an indirect or
// extbuf-attached mbuf, whose memory is another's: mlx5 MPRQ attaches a
// packet to a stride of a multi-packet buffer, which holding would pin
// whole; an mbuf of another pool); a negative errno, the mbuf freed, as
// ntcp_dpdk_receive refuses it.
int ntcp_dpdk_receive_meta(void *packet, const void *pool, int timestamp_offset,
                           uint64_t timestamp_flag, int l4_checksum,
                           struct ntcp_rx_meta *out) {
    struct rte_mbuf *m = packet;
    int result = receive_check(m, NTCP_DPDK_MAX_PACKET_LEN);
    if (result < 0) {
        rte_pktmbuf_free(m);
        return result;
    }
    if (!direct_frame(m, pool))
        return NTCP_DPDK_COPY;
    receive_metadata(m, timestamp_offset, timestamp_flag, &out->timestamp,
                     &out->timestamp_valid, l4_checksum, &out->l4_status);
    out->data = rte_pktmbuf_mtod(m, void *);
    out->length = m->data_len;
    return 1;
}

// What an element of `pool` takes (its object header, the element and its
// trailer: the memory one mbuf keeps from the pool), the per-lcore cache
// size, and the element count.
void ntcp_dpdk_pool_geometry(const void *pool, uint32_t *element, uint32_t *cache,
                             uint32_t *size) {
    const struct rte_mempool *mp = pool;
    *element = mp->header_size + mp->elt_size + mp->trailer_size;
    *cache = mp->cache_size;
    *size = mp->size;
}

uint16_t ntcp_dpdk_pool_room(const void *pool) {
    uint16_t room = rte_pktmbuf_data_room_size((struct rte_mempool *)pool);
    return room > RTE_PKTMBUF_HEADROOM ? (uint16_t)(room - RTE_PKTMBUF_HEADROOM) : 0;
}

// Whether TCP checksum offload is enabled on TX queue `queue`, as
// ntcp_dpdk_rx_checksum_check reads RX.
int ntcp_dpdk_tx_checksum_check(uint16_t port, uint16_t queue) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    if (queue >= info.nb_tx_queues) return -EINVAL;
    if (!(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)) return -ENOTSUP;
    struct rte_eth_conf conf;
    result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    if (conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) return 0;
    struct rte_eth_txq_info qinfo;
    result = rte_eth_tx_queue_info_get(port, queue, &qinfo);
    if (result < 0) return result;
    return (qinfo.conf.offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) ? 0 : -ENOTSUP;
}

// Fill one newly allocated segment, up to the room provided by its pool.
static inline size_t copy_segment(struct rte_mbuf *m, const uint8_t *packet, size_t length) {
    size_t count = rte_pktmbuf_tailroom(m);
    if (count > length)
        count = length;
    // A freshly allocated mbuf is one empty segment. We already
    // bounded the copy by its tailroom.
    if (count) {
        memcpy(rte_pktmbuf_mtod(m, void *), packet, count);
        m->data_len = (uint16_t)count;
        m->pkt_len = (uint32_t)count;
    }
    return count;
}

// `l3`: nonzero for a TCP segment over IPv4 (its header length) or IPv6
// (40) whose checksum field holds the pseudo-header sum, which the device
// completes (RTE_MBUF_F_TX_TCP_CKSUM, as Linux hands a device a
// CHECKSUM_PARTIAL skb). Rust checked the frame.
int ntcp_dpdk_transmit(uint16_t port, uint16_t queue, void *pool,
                       const uint8_t *packet, size_t length, int timestamp_offset,
                       uint64_t timestamp_flag, uint64_t timestamp, uint16_t l3) {
    if (!length)
        return -EINVAL;
    if (length > NTCP_DPDK_MAX_PACKET_LEN)
        return -EMSGSIZE;
    struct rte_mbuf *head = rte_pktmbuf_alloc(pool);
    if (!head)
        return NTCP_DPDK_NOMBUF;
    size_t offset = copy_segment(head, packet, length);
    if (!offset) {
        rte_pktmbuf_free(head);
        return -EINVAL;
    }
    struct rte_mbuf *tail = head;
    while (offset < length) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        if (!m) {
            rte_pktmbuf_free(head);
            return NTCP_DPDK_NOMBUF;
        }
        size_t chunk = copy_segment(m, packet + offset, length - offset);
        if (!chunk) {
            rte_pktmbuf_free(m);
            rte_pktmbuf_free(head);
            return -EINVAL;
        }
        tail->next = m;
        head->nb_segs++;
        head->pkt_len += (uint32_t)chunk;
        tail = m;
        offset += chunk;
    }
    if (timestamp_offset >= 0) {
        *RTE_MBUF_DYNFIELD(head, timestamp_offset, rte_mbuf_timestamp_t *) = timestamp;
        head->ol_flags |= timestamp_flag;
    }
    if (l3) {
        head->l2_len = 14;
        head->l3_len = l3;
        head->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM |
            (packet[14] >> 4 == 4 ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6);
        // As for TSO: a PMD that wants the field prepared differently
        // prepares it here.
        if (rte_eth_tx_prepare(port, queue, &head, 1) != 1) {
            int error = rte_errno ? -rte_errno : -EIO;
            rte_pktmbuf_free(head);
            return error;
        }
    }
    if (rte_eth_tx_burst(port, queue, &head, 1) == 1)
        return 1; // Driver owns it; never free a submitted mbuf here.
    rte_pktmbuf_free(head);
    return 0;
}

#include <rte_ip.h>
#include <rte_tcp.h>

// Pure gate also exercised with injected configuration in the C fixture.
int ntcp_dpdk_tso_gate(uint64_t supported, uint64_t port_flags, uint64_t queue_flags,
                      uint16_t nb_seg, uint16_t nb_mtu_seg, uint16_t queue_desc,
                      uint16_t *limit) {
    const uint64_t required = RTE_ETH_TX_OFFLOAD_TCP_TSO |
        RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    uint64_t enabled = port_flags | queue_flags;
    if ((supported & required) != required || (enabled & required) != required ||
        !nb_seg || !nb_mtu_seg || !queue_desc) return -ENOTSUP;
    // ponytail: bound the whole chain by the per-MTU descriptor limit too.
    // This is conservative; count per-output-segment spans if needed later.
    *limit = RTE_MIN(RTE_MIN(nb_seg, nb_mtu_seg), queue_desc);
    if (!(supported & enabled & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) *limit = 1;
    return 0;
}

int ntcp_dpdk_tso_check(uint16_t port, uint16_t queue, void *pool,
                        struct ntcp_tso_config *config) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    if (queue >= info.nb_tx_queues) return -EINVAL;
    struct rte_eth_conf conf;
    result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    struct rte_eth_txq_info qinfo;
    result = rte_eth_tx_queue_info_get(port, queue, &qinfo);
    if (result < 0) return result; // Unknown actual configuration fails closed.
    result = ntcp_dpdk_tso_gate(info.tx_offload_capa, conf.txmode.offloads,
        qinfo.conf.offloads, info.tx_desc_lim.nb_seg_max,
        info.tx_desc_lim.nb_mtu_seg_max, qinfo.nb_desc, &config->max_descriptors);
    if (result < 0) return result;
    result = rte_eth_dev_get_mtu(port, &config->mtu);
    if (result < 0) return result;
    uint16_t room = rte_pktmbuf_data_room_size(pool);
    if (!config->mtu || room <= RTE_PKTMBUF_HEADROOM + 74) return -ENOTSUP;
    config->room = room - RTE_PKTMBUF_HEADROOM;
    return 0;
}

int ntcp_dpdk_tso_transmit(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *packet, size_t length, uint16_t l3, uint16_t mss,
    const struct ntcp_tso_config *config) {
    // Rust validates bytes before this internal ABI. Recheck allocation geometry
    // before allocating, including contiguous complete headers in the head mbuf.
    // l4_len is the TCP data offset: the device repeats the options too.
    if ((l3 != 20 && l3 != 40) || !mss || !config->room ||
        length <= 14u + l3 + 20u || length > NTCP_DPDK_MAX_PACKET_LEN)
        return -EINVAL;
    uint16_t l4 = (packet[14 + l3 + 12] >> 4) * 4;
    if (l4 < 20 || length <= 14u + l3 + l4 || config->room < 14u + l3 + l4 ||
        (length + config->room - 1) / config->room > config->max_descriptors)
        return -EINVAL;
    struct rte_mbuf *head = NULL, *tail = NULL;
    size_t offset = 0;
    while (offset < length) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        if (!m) { rte_pktmbuf_free(head); return NTCP_DPDK_NOMBUF; }
        size_t chunk = RTE_MIN(length - offset, config->room);
        void *dst = rte_pktmbuf_append(m, (uint16_t)chunk);
        if (!dst) { rte_pktmbuf_free(m); rte_pktmbuf_free(head); return -EINVAL; }
        memcpy(dst, packet + offset, chunk);
        if (!head) head = m;
        else { tail->next = m; head->nb_segs++; head->pkt_len += (uint32_t)chunk; }
        tail = m;
        offset += chunk;
    }
    head->l2_len = 14;
    head->l3_len = l3;
    head->l4_len = l4;
    head->tso_segsz = mss;
    head->ol_flags = RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM;
    struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(head, struct rte_tcp_hdr *, 14 + l3);
    if (l3 == 20) {
        head->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
        struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(head, struct rte_ipv4_hdr *, 14);
        ip->hdr_checksum = 0;
        tcp->cksum = rte_ipv4_phdr_cksum(ip, head->ol_flags);
    } else {
        head->ol_flags |= RTE_MBUF_F_TX_IPV6;
        struct rte_ipv6_hdr *ip = rte_pktmbuf_mtod_offset(head, struct rte_ipv6_hdr *, 14);
        tcp->cksum = rte_ipv6_phdr_cksum(ip, head->ol_flags);
    }
    // tx_prepare is optional PMD assistance, not proof of offload support.
    // Capability/configuration proof comes from the control-plane gate above.
    if (rte_eth_tx_prepare(port, queue, &head, 1) != 1) {
        int error = rte_errno ? -rte_errno : -EIO;
        rte_pktmbuf_free(head);
        return error;
    }
    if (rte_eth_tx_burst(port, queue, &head, 1) == 1) return 1;
    rte_pktmbuf_free(head);
    return 0;
}

#include <stdlib.h>
#include <rte_malloc.h>
#include <rte_memory.h>

static int validate_iova_span(const void *p, size_t length, uint64_t *iova) {
    rte_iova_t base = rte_mem_virt2iova(p);
    // The external mbuf describes one contiguous IOVA span. Refuse fragmented
    // mappings rather than assuming that virtually contiguous implies DMA-safe.
    if (base == RTE_BAD_IOVA) return -1;
    for (size_t offset = 0; offset < length;) {
        const char *at = (const char *)p + offset;
        const struct rte_memseg *ms = rte_mem_virt2memseg(at, NULL);
        if (!ms || rte_mem_virt2iova(at) != base + offset)
            return -1;
        size_t left = (uintptr_t)ms->addr + ms->len - (uintptr_t)at;
        if (!left) return -1;
        offset += RTE_MIN(left, length - offset);
    }
    *iova = base;
    return 0;
}

void *ntcp_dpdk_payload_alloc(size_t length, uint64_t *iova) {
    if (!length || length > NTCP_DPDK_MAX_PACKET_LEN) return NULL;
    void *p = rte_zmalloc(NULL, length, RTE_CACHE_LINE_SIZE);
    if (!p) return NULL;
    if (validate_iova_span(p, length, iova) < 0) {
        rte_free(p);
        return NULL;
    }
    return p;
}
void ntcp_dpdk_payload_free(void *address) { rte_free(address); }

int ntcp_dpdk_reclaim(uint16_t port, uint16_t queue, uint32_t budget) {
    if (!budget) return 0; // DPDK zero means unbounded: never forward it.
    return rte_eth_tx_done_cleanup(port, queue, budget);
}
// Completions of a queue that frees sent mbufs on a later burst, without
// sending: mlx5's tx_descriptor_status runs its completion handler first
// (drivers/net/mlx5/mlx5_tx.c:270-279). It cannot count what it freed.
int ntcp_dpdk_reclaim_later_burst(uint16_t port, uint16_t queue) {
    int result = rte_eth_tx_descriptor_status(port, queue, 0);
    return result < 0 ? result : 0;
}
// The check of ntcp_dpdk_shared_check that failed, in `*stage`.
enum {
    NTCP_SHARED_INFO = 1, NTCP_SHARED_QUEUE, NTCP_SHARED_CONF, NTCP_SHARED_QUEUE_INFO,
    NTCP_SHARED_MULTI_SEGS_CAPA, NTCP_SHARED_MULTI_SEGS, NTCP_SHARED_LIMITS,
    NTCP_SHARED_FAST_FREE, NTCP_SHARED_ROOM, NTCP_SHARED_SEGMENTS, NTCP_SHARED_CLEANUP,
    NTCP_SHARED_DESCRIPTOR_STATUS,
};

// `later_burst`: the driver frees sent mbufs on a later burst (shared.rs
// tx_release), so idle TX is served by ntcp_dpdk_reclaim_later_burst and
// tx_done_cleanup is not consulted.
int ntcp_dpdk_shared_check(uint16_t port, uint16_t queue, void *pool, int later_burst,
                           uint16_t *limit, int *stage) {
    struct rte_eth_dev_info info;
    *stage = NTCP_SHARED_INFO;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    *stage = NTCP_SHARED_QUEUE;
    if (queue >= info.nb_tx_queues) return -EINVAL;
    struct rte_eth_conf conf;
    *stage = NTCP_SHARED_CONF;
    result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    struct rte_eth_txq_info qinfo;
    *stage = NTCP_SHARED_QUEUE_INFO;
    result = rte_eth_tx_queue_info_get(port, queue, &qinfo);
    if (result < 0) return result;
    uint64_t offloads = conf.txmode.offloads | qinfo.conf.offloads;
    *stage = NTCP_SHARED_MULTI_SEGS_CAPA;
    if (!(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) return -ENOTSUP;
    *stage = NTCP_SHARED_MULTI_SEGS;
    if (!(offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) return -ENOTSUP;
    *stage = NTCP_SHARED_LIMITS;
    if (!info.tx_desc_lim.nb_seg_max || !info.tx_desc_lim.nb_mtu_seg_max || !qinfo.nb_desc)
        return -ENOTSUP;
    *stage = NTCP_SHARED_FAST_FREE;
    if (offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) return -ENOTSUP;
    *stage = NTCP_SHARED_ROOM;
    if (rte_pktmbuf_data_room_size(pool) < RTE_PKTMBUF_HEADROOM + 134) return -ENOTSUP;
    *limit = RTE_MIN(RTE_MIN(info.tx_desc_lim.nb_seg_max,
                          info.tx_desc_lim.nb_mtu_seg_max), qinfo.nb_desc);
    *stage = NTCP_SHARED_SEGMENTS;
    if (*limit < 3) return -ENOTSUP;
    // Idle TX must progress without waiting for another packet to be sent.
    // This may reclaim a completed packet but never changes port settings.
    if (later_burst) {
        // The ethdev dummy (no tx_descriptor_status) returns -ENOTSUP.
        *stage = NTCP_SHARED_DESCRIPTOR_STATUS;
        return ntcp_dpdk_reclaim_later_burst(port, queue);
    }
    *stage = NTCP_SHARED_CLEANUP;
    result = ntcp_dpdk_reclaim(port, queue, 1);
    return result < 0 ? result : 0;
}

struct ntcp_external {
    struct rte_mbuf_ext_shared_info shared;
    void *lease;
    ntcp_release_fn release;
};
static void external_free(void *address, void *opaque) {
    (void)address;
    struct ntcp_external *e = opaque;
    e->release(e->lease);
    free(e);
}
int ntcp_dpdk_shared_transmit(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, uint16_t header_length,
    const struct ntcp_shared_segment *segments, uint16_t count,
    ntcp_release_fn release) {
    struct rte_mbuf *head = NULL;
    uint16_t consumed = 0;
    int result = -EINVAL;
    size_t total = header_length;
    if (!header_length || !count) goto done;
    for (uint16_t i = 0; i < count; ++i) {
        if (!segments[i].length || !segments[i].address ||
            segments[i].iova == RTE_BAD_IOVA) goto done;
        total += segments[i].length;
    }
    if (total > NTCP_DPDK_MAX_PACKET_LEN) { result = -EMSGSIZE; goto done; }
    result = NTCP_DPDK_NOMBUF;
    head = rte_pktmbuf_alloc(pool);
    if (!head) goto done;
    void *dst = rte_pktmbuf_append(head, header_length);
    if (!dst) { result = -EINVAL; goto done; }
    memcpy(dst, header, header_length);
    for (; consumed < count;) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        struct ntcp_external *e = calloc(1, sizeof(*e));
        if (!m || !e) {
            if (m) result = 0; // The heap, not the pool, failed.
            rte_pktmbuf_free(m);
            free(e);
            goto done;
        }
        const struct ntcp_shared_segment *s = &segments[consumed];
        e->lease = s->lease;
        e->release = release;
        e->shared.free_cb = external_free;
        e->shared.fcb_opaque = e;
        rte_mbuf_ext_refcnt_set(&e->shared, 1);
        rte_pktmbuf_attach_extbuf(m, (void *)s->address, s->iova, s->length, &e->shared);
        m->data_off = 0;
        m->data_len = s->length;
        m->pkt_len = s->length;
        consumed++;
        if (rte_pktmbuf_chain(head, m)) { rte_pktmbuf_free(m); result = -EINVAL; goto done; }
    }
    // Ethernet padding follows the payload. It must not alter referenced bytes
    // or the IP/TCP lengths/checksums encoded by the caller.
    if (total < 60) {
        struct rte_mbuf *pad = rte_pktmbuf_alloc(pool);
        if (!pad) goto done;
        dst = rte_pktmbuf_append(pad, (uint16_t)(60 - total));
        if (!dst) { rte_pktmbuf_free(pad); result = -EINVAL; goto done; }
        memset(dst, 0, 60 - total);
        if (rte_pktmbuf_chain(head, pad)) { rte_pktmbuf_free(pad); result = -EINVAL; goto done; }
    }
    result = 0;
    if (rte_eth_tx_burst(port, queue, &head, 1) == 1) {
        head = NULL;
        result = 1;
    }
done:
    rte_pktmbuf_free(head);
    for (; consumed < count; ++consumed) release(segments[consumed].lease);
    return result;
}

// DMA-backed transmit chunk with embedded rte_mbuf_ext_shared_info so attaching
// an extbuf slice to an mbuf needs zero per-packet heap allocation (I10).
// Two-level refcount: refcnt starts at 1 for the TxChunk owner; each attached
// mbuf increments refcnt before rte_pktmbuf_attach_extbuf (which does not touch
// shinfo->refcnt in DPDK 26.03) and rte_pktmbuf_free/__rte_pktmbuf_free_extbuf
// decrements it. Whichever of TxChunk drop or the last mbuf free hits 0 calls
// recycle_cb(chunk, recycler).
struct ntcp_dpdk_chunk {
    struct rte_mbuf_ext_shared_info shared;
    uint64_t data_iova;
    void *recycler;
    ntcp_chunk_free_fn recycle_cb;
    uint32_t capacity;
    uint8_t data[] __rte_aligned(RTE_CACHE_LINE_SIZE);
};
_Static_assert(offsetof(struct ntcp_dpdk_chunk, data) % RTE_CACHE_LINE_SIZE == 0,
               "chunk data must be cache-line aligned");

static void chunk_ext_free_cb(void *address, void *opaque) {
    (void)address;
    struct ntcp_dpdk_chunk *c = opaque;
    // Acquire barrier pairs with acq_rel decrements from other threads in case
    // rte_mbuf_ext_refcnt_update took its relaxed fast path on refcnt == 1.
    rte_atomic_thread_fence(rte_memory_order_acquire);
    c->recycle_cb(c, c->recycler);
}

void *ntcp_dpdk_chunk_alloc(size_t capacity, void *recycler,
                            ntcp_chunk_free_fn recycle_cb, uint8_t **data_out) {
    if (!capacity || !recycle_cb || !data_out ||
        capacity > UINT32_MAX - sizeof(struct ntcp_dpdk_chunk))
        return NULL;
    // rte_malloc (not rte_zmalloc): chunks are append-only and written before read.
    struct ntcp_dpdk_chunk *c =
        rte_malloc(NULL, sizeof(*c) + capacity, RTE_CACHE_LINE_SIZE);
    if (!c) return NULL;
    uint64_t iova = 0;
    if (validate_iova_span(c->data, capacity, &iova) < 0) {
        rte_free(c);
        return NULL;
    }
    c->shared.free_cb = chunk_ext_free_cb;
    c->shared.fcb_opaque = c;
    rte_mbuf_ext_refcnt_set(&c->shared, 1);
    c->data_iova = iova;
    c->recycler = recycler;
    c->recycle_cb = recycle_cb;
    c->capacity = (uint32_t)capacity;
    *data_out = c->data;
    return c;
}

void ntcp_dpdk_chunk_reset(void *chunk, void *recycler, uint8_t **data_out) {
    struct ntcp_dpdk_chunk *c = chunk;
    c->recycler = recycler;
    rte_mbuf_ext_refcnt_set(&c->shared, 1);
    *data_out = c->data;
}

void ntcp_dpdk_chunk_release(void *chunk) {
    struct ntcp_dpdk_chunk *c = chunk;
    if (rte_mbuf_ext_refcnt_update(&c->shared, -1) == 0) {
        rte_atomic_thread_fence(rte_memory_order_acquire);
        c->recycle_cb(c, c->recycler);
    }
}

void ntcp_dpdk_chunk_free(void *chunk) {
    rte_free(chunk);
}

uint16_t ntcp_dpdk_chunk_refcnt(const void *chunk) {
    const struct ntcp_dpdk_chunk *c = chunk;
    return rte_mbuf_ext_refcnt_read(&c->shared);
}

// Apply TX scheduling, TSO, or TCP checksum offload metadata to `head`, run
// rte_eth_tx_prepare when an offload is requested, and submit via tx_burst.
// Always consumes `head` (either handed to the PMD on 1, or freed on 0/error).
static int prepare_and_send(uint16_t port, uint16_t queue, struct rte_mbuf *head,
                            const struct ntcp_tx_offload *offload) {
    if (offload->timestamp_offset >= 0) {
        *RTE_MBUF_DYNFIELD(head, offload->timestamp_offset, rte_mbuf_timestamp_t *) =
            offload->timestamp;
        head->ol_flags |= offload->timestamp_flag;
    }
    if (offload->mss) {
        if (head->data_len < 14u + offload->l3 + offload->l4) {
            rte_pktmbuf_free(head);
            return -EINVAL;
        }
        head->l2_len = 14;
        head->l3_len = offload->l3;
        head->l4_len = offload->l4;
        head->tso_segsz = offload->mss;
        head->ol_flags |= RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM;
        struct rte_tcp_hdr *tcp =
            rte_pktmbuf_mtod_offset(head, struct rte_tcp_hdr *, 14 + offload->l3);
        if (offload->l3 == 20) {
            head->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
            struct rte_ipv4_hdr *ip =
                rte_pktmbuf_mtod_offset(head, struct rte_ipv4_hdr *, 14);
            ip->hdr_checksum = 0;
            tcp->cksum = rte_ipv4_phdr_cksum(ip, head->ol_flags);
        } else {
            head->ol_flags |= RTE_MBUF_F_TX_IPV6;
            struct rte_ipv6_hdr *ip =
                rte_pktmbuf_mtod_offset(head, struct rte_ipv6_hdr *, 14);
            tcp->cksum = rte_ipv6_phdr_cksum(ip, head->ol_flags);
        }
        if (rte_eth_tx_prepare(port, queue, &head, 1) != 1) {
            int error = rte_errno ? -rte_errno : -EIO;
            rte_pktmbuf_free(head);
            return error;
        }
    } else if (offload->l3) {
        if (head->data_len < 15u) {
            rte_pktmbuf_free(head);
            return -EINVAL;
        }
        const uint8_t *hdr = rte_pktmbuf_mtod(head, const uint8_t *);
        head->l2_len = 14;
        head->l3_len = offload->l3;
        head->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM |
            ((hdr[14] >> 4) == 4 ? RTE_MBUF_F_TX_IPV4 : RTE_MBUF_F_TX_IPV6);
        if (rte_eth_tx_prepare(port, queue, &head, 1) != 1) {
            int error = rte_errno ? -rte_errno : -EIO;
            rte_pktmbuf_free(head);
            return error;
        }
    }
    if (rte_eth_tx_burst(port, queue, &head, 1) == 1)
        return 1;
    rte_pktmbuf_free(head);
    return 0;
}

int ntcp_dpdk_packet_transmit_ext(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, uint16_t header_length,
    const struct ntcp_ext_part *parts, uint16_t count,
    ntcp_release_fn shared_release,
    const struct ntcp_tx_offload *offload) {
    struct rte_mbuf *head = NULL;
    uint16_t consumed = 0;
    int result = -EINVAL;
    size_t total = header_length;
    if (!header_length || !count || !offload) goto done;
    for (uint16_t i = 0; i < count; ++i) {
        if (!parts[i].length) goto done;
        if (parts[i].kind == NTCP_EXT_CHUNK) {
            const struct ntcp_dpdk_chunk *c = parts[i].handle;
            if (!c || (uint64_t)parts[i].offset + parts[i].length > c->capacity)
                goto done;
        } else if (parts[i].kind == NTCP_EXT_SHARED) {
            if (!parts[i].address || parts[i].iova == RTE_BAD_IOVA || !shared_release)
                goto done;
        } else {
            goto done;
        }
        total += parts[i].length;
    }
    if (total > NTCP_DPDK_MAX_PACKET_LEN) { result = -EMSGSIZE; goto done; }
    if (offload->mss) {
        if ((offload->l3 != 20 && offload->l3 != 40) || offload->l4 < 20 ||
            header_length < 14u + offload->l3 + offload->l4 ||
            total <= 14u + offload->l3 + offload->l4)
            goto done;
    }
    result = NTCP_DPDK_NOMBUF;
    head = rte_pktmbuf_alloc(pool);
    if (!head) goto done;
    void *dst = rte_pktmbuf_append(head, header_length);
    if (!dst) { result = -EINVAL; goto done; }
    memcpy(dst, header, header_length);
    struct rte_mbuf *tail = head;
    for (; consumed < count;) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        if (!m) { result = NTCP_DPDK_NOMBUF; goto done; }
        const struct ntcp_ext_part *p = &parts[consumed];
        if (p->kind == NTCP_EXT_CHUNK) {
            struct ntcp_dpdk_chunk *c = p->handle;
            if (rte_mbuf_ext_refcnt_read(&c->shared) == UINT16_MAX) {
                rte_pktmbuf_free(m);
                result = 0;
                goto done;
            }
            rte_mbuf_ext_refcnt_update(&c->shared, 1);
            rte_pktmbuf_attach_extbuf(m, c->data + p->offset,
                                      c->data_iova + p->offset, p->length, &c->shared);
            m->data_off = 0;
            m->data_len = p->length;
            m->pkt_len = p->length;
            consumed++;
        } else {
            struct ntcp_external *e = calloc(1, sizeof(*e));
            if (!e) {
                rte_pktmbuf_free(m);
                result = 0;
                goto done;
            }
            e->lease = p->handle;
            e->release = shared_release;
            e->shared.free_cb = external_free;
            e->shared.fcb_opaque = e;
            rte_mbuf_ext_refcnt_set(&e->shared, 1);
            rte_pktmbuf_attach_extbuf(m, (void *)p->address, p->iova, p->length, &e->shared);
            m->data_off = 0;
            m->data_len = p->length;
            m->pkt_len = p->length;
            consumed++;
        }
        if (head->nb_segs == RTE_MBUF_MAX_NB_SEGS) {
            rte_pktmbuf_free(m);
            result = -EINVAL;
            goto done;
        }
        tail->next = m;
        head->nb_segs++;
        head->pkt_len += m->data_len;
        tail = m;
    }
    // Ethernet padding for short non-TSO frames (never pad TSO aggregates).
    if (total < 60 && !offload->mss) {
        struct rte_mbuf *pad = rte_pktmbuf_alloc(pool);
        if (!pad) { result = NTCP_DPDK_NOMBUF; goto done; }
        dst = rte_pktmbuf_append(pad, (uint16_t)(60 - total));
        if (!dst) { rte_pktmbuf_free(pad); result = -EINVAL; goto done; }
        memset(dst, 0, 60 - total);
        if (head->nb_segs == RTE_MBUF_MAX_NB_SEGS) {
            rte_pktmbuf_free(pad);
            result = -EINVAL;
            goto done;
        }
        tail->next = pad;
        head->nb_segs++;
        head->pkt_len += pad->data_len;
        tail = pad;
    }
    result = prepare_and_send(port, queue, head, offload);
    head = NULL;
done:
    rte_pktmbuf_free(head);
    for (; consumed < count; ++consumed) {
        if (parts[consumed].kind == NTCP_EXT_SHARED)
            shared_release(parts[consumed].handle);
    }
    return result;
}

static int copy_bytes_into_chain(void *pool, struct rte_mbuf *head,
                                 struct rte_mbuf **cur_ptr, uint8_t **dst_ptr,
                                 size_t *cur_rem_ptr,
                                 const uint8_t *src, size_t rem) {
    struct rte_mbuf *cur = *cur_ptr;
    uint8_t *dst = *dst_ptr;
    size_t cur_rem = *cur_rem_ptr;
    while (rem > 0) {
        if (cur_rem == 0) {
            if (head->nb_segs == RTE_MBUF_MAX_NB_SEGS)
                return -EINVAL;
            struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
            if (!m) return NTCP_DPDK_NOMBUF;
            cur_rem = rte_pktmbuf_tailroom(m);
            if (!cur_rem) {
                rte_pktmbuf_free(m);
                return -EINVAL;
            }
            cur->next = m;
            head->nb_segs++;
            cur = m;
            dst = rte_pktmbuf_mtod(cur, uint8_t *);
        }
        size_t n = RTE_MIN(rem, cur_rem);
        memcpy(dst, src, n);
        dst += n;
        src += n;
        rem -= n;
        cur_rem -= n;
        cur->data_len += (uint16_t)n;
        cur->pkt_len += (uint32_t)n;
        if (cur != head)
            head->pkt_len += (uint32_t)n;
    }
    *cur_ptr = cur;
    *dst_ptr = dst;
    *cur_rem_ptr = cur_rem;
    return 0;
}

int ntcp_dpdk_packet_transmit_copy(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, size_t header_length,
    const struct ntcp_copy_part *parts, size_t count,
    const struct ntcp_tx_offload *offload,
    uint16_t max_descriptors) {
    if (!offload) return -EINVAL;
    size_t total = header_length;
    for (size_t i = 0; i < count; ++i) {
        if (parts[i].length > NTCP_DPDK_MAX_PACKET_LEN ||
            total > NTCP_DPDK_MAX_PACKET_LEN - parts[i].length)
            return -EMSGSIZE;
        total += parts[i].length;
    }
    if (!total) return -EINVAL;
    if (total > NTCP_DPDK_MAX_PACKET_LEN) return -EMSGSIZE;
    if (offload->mss) {
        if ((offload->l3 != 20 && offload->l3 != 40) || offload->l4 < 20 ||
            total <= 14u + offload->l3 + offload->l4)
            return -EINVAL;
    }
    struct rte_mbuf *head = rte_pktmbuf_alloc(pool);
    if (!head) return NTCP_DPDK_NOMBUF;
    size_t room = rte_pktmbuf_tailroom(head);
    if (!room) {
        rte_pktmbuf_free(head);
        return -EINVAL;
    }
    if (offload->mss) {
        if (room < 14u + offload->l3 + offload->l4 ||
            (max_descriptors && (total + room - 1) / room > max_descriptors)) {
            rte_pktmbuf_free(head);
            return -EINVAL;
        }
    }
    // The complete frame normally fits in the head. Set its lengths once
    // and copy the spans without walking or updating a segment chain.
    size_t wire_len = offload->mss ? total : RTE_MAX(total, (size_t)60);
    if (wire_len <= room) {
        uint8_t *dst = rte_pktmbuf_mtod(head, uint8_t *);
        if (header_length) {
            memcpy(dst, header, header_length);
            dst += header_length;
        }
        for (size_t i = 0; i < count; ++i) {
            if (parts[i].length) {
                memcpy(dst, parts[i].ptr, parts[i].length);
                dst += parts[i].length;
            }
        }
        if (total < wire_len) memset(dst, 0, wire_len - total);
        head->data_len = (uint16_t)wire_len;
        head->pkt_len = (uint32_t)wire_len;
        return prepare_and_send(port, queue, head, offload);
    }
    struct rte_mbuf *cur = head;
    uint8_t *dst = rte_pktmbuf_mtod(head, uint8_t *);
    size_t cur_rem = room;
    int status = copy_bytes_into_chain(pool, head, &cur, &dst, &cur_rem,
                                       header, header_length);
    if (status != 0) {
        rte_pktmbuf_free(head);
        return status;
    }
    for (size_t i = 0; i < count; ++i) {
        if (!parts[i].length) continue;
        status = copy_bytes_into_chain(pool, head, &cur, &dst, &cur_rem,
                                       parts[i].ptr, parts[i].length);
        if (status != 0) {
            rte_pktmbuf_free(head);
            return status;
        }
    }
    // Ethernet padding for short non-TSO frames (matches extbuf path).
    if (total < 60 && !offload->mss) {
        static const uint8_t zero_pad[60] = {0};
        status = copy_bytes_into_chain(pool, head, &cur, &dst, &cur_rem,
                                       zero_pad, 60 - total);
        if (status != 0) {
            rte_pktmbuf_free(head);
            return status;
        }
    }
    return prepare_and_send(port, queue, head, offload);
}

// Host setup. Unlike everything above, these functions own EAL, ports, pools
// and flows; Rust (host.rs) sequences them and guarantees teardown order.
#include <rte_bus.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_lcore.h>
#include <rte_mempool.h>

int ntcp_dpdk_eal_init(int argc, char **argv) {
    // Pins the calling thread to the main lcore. Never retried by the caller.
    int result = rte_eal_init(argc, argv);
    return result < 0 ? -rte_errno : result;
}
unsigned ntcp_dpdk_main_lcore(void) { return rte_get_main_lcore(); }
// UINT32_MAX (LCORE_ID_ANY) means the calling thread is not an EAL thread.
unsigned ntcp_dpdk_lcore_id(void) { return rte_lcore_id(); }
int ntcp_dpdk_thread_register(void) {
    return rte_thread_register() < 0 ? -rte_errno : 0;
}
void ntcp_dpdk_thread_unregister(void) { rte_thread_unregister(); }

static int find_port(const char *devargs, uint16_t *port, unsigned *count) {
    struct rte_dev_iterator iterator;
    uint16_t id;
    *count = 0;
    RTE_ETH_FOREACH_MATCHING_DEV(id, devargs, &iterator) {
        *port = id;
        ++*count;
    }
    return 0;
}

// Find (probing if needed) exactly one ethdev port for devargs and take
// exclusive ethdev ownership of it, so no other owner can configure it.
int ntcp_dpdk_port_claim(const char *devargs, uint64_t *owner, uint16_t *port) {
    unsigned count;
    find_port(devargs, port, &count);
    if (!count) {
        int result = rte_dev_probe(devargs);
        // Already probed but without a matching port is reported below.
        if (result < 0 && result != -EEXIST) return result;
        find_port(devargs, port, &count);
    }
    if (!count) return -ENODEV;
    if (count > 1) return -EINVAL; // Ambiguous: name one port's devargs.
    int result = rte_eth_dev_owner_new(owner);
    if (result < 0) return result;
    struct rte_eth_dev_owner claim = { .id = *owner };
    snprintf(claim.name, sizeof(claim.name), "ntcp");
    result = rte_eth_dev_owner_set(*port, &claim);
    if (result < 0) {
        rte_eth_dev_owner_delete(*owner);
        *owner = 0;
    }
    // rte_eth_dev_owner_set fails with EPERM for one reason only: the port
    // already has another owner. That is contention, not missing privilege, so
    // report EBUSY (ResourceBusy) rather than send callers to check privileges.
    return result == -EPERM ? -EBUSY : result;
}

static void flow_message(const struct rte_flow_error *error, char *message, size_t capacity) {
    snprintf(message, capacity, "%s", error->message ? error->message : "");
}

// Bifurcated PMDs (mlx5) must enter isolated mode before configuration.
int ntcp_dpdk_port_isolate(uint16_t port, char *message, size_t capacity) {
    struct rte_flow_error error = {0};
    int result = rte_flow_isolate(port, 1, &error);
    if (result < 0) flow_message(&error, message, capacity);
    return result;
}

int ntcp_dpdk_port_socket(uint16_t port) { return rte_eth_dev_socket_id(port); }

void *ntcp_dpdk_pool_create(const char *name, uint32_t count, uint16_t data_size,
                            int socket, int *error) {
    if ((uint32_t)data_size + RTE_PKTMBUF_HEADROOM > UINT16_MAX) {
        *error = -EINVAL;
        return NULL;
    }
    // A queue's pool is used by one worker lcore. The cache only amortises
    // ring access (testpmd uses 250); flush thresholds require 1.5x <= count.
    unsigned cache = RTE_MIN(256u, count / 2);
    struct rte_mempool *pool = rte_pktmbuf_pool_create(name, count, cache, 0,
        (uint16_t)(data_size + RTE_PKTMBUF_HEADROOM), socket);
    *error = pool ? 0 : -rte_errno;
    return pool;
}

unsigned ntcp_dpdk_pool_in_use(const void *pool) {
    return rte_mempool_in_use_count(pool);
}

// Freeing a pool with outstanding mbufs would leave live references to freed
// memory. Retain (leak) it instead; returns 1 if freed, 0 if retained.
int ntcp_dpdk_pool_free(void *pool) {
    if (!rte_mempool_full(pool)) return 0;
    rte_mempool_free(pool);
    return 1;
}

enum {
    NTCP_STAGE_INFO = 1, NTCP_STAGE_QUEUES, NTCP_STAGE_TIMESTAMP, NTCP_STAGE_SCATTER,
    NTCP_STAGE_MULTI_SEGS, NTCP_STAGE_CONFIGURE, NTCP_STAGE_DESCRIPTORS,
    NTCP_STAGE_RSS, NTCP_STAGE_RSS_KEY,
};

// The hash types ntcp's flow ownership is defined over: TCP over addresses and
// ports, fragments (which carry no ports past the first) over addresses.
static const uint64_t ntcp_rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_IPV4 |
    RTE_ETH_RSS_FRAG_IPV4;

// Configure queue pairs for the borrowed adapter's RX contract: complete,
// untransformed frames. Only TIMESTAMP (requested) and SCATTER (needed for
// frames larger than one mbuf) are enabled on RX; nothing strips or merges.
int ntcp_dpdk_port_configure(uint16_t port, const struct ntcp_port_config *config,
                             uint16_t *rx_desc, uint16_t *tx_desc, int *stage,
                             uint8_t *key_size, uint8_t *tcp_segmentation,
                             uint8_t *checksums) {
    struct rte_eth_dev_info info;
    *stage = NTCP_STAGE_INFO;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    *stage = NTCP_STAGE_QUEUES;
    if (!config->queues || config->queues > info.max_rx_queues ||
        config->queues > info.max_tx_queues) return -EINVAL;
    uint64_t rx = 0, tx = 0;
    if (config->rx_timestamps) {
        *stage = NTCP_STAGE_TIMESTAMP;
        if (!(info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) return -ENOTSUP;
        rx |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    }
    // Same L2 overhead rule as ethdev's MTU validation.
    uint32_t overhead = info.max_mtu != UINT16_MAX && info.max_rx_pktlen > info.max_mtu ?
        info.max_rx_pktlen - info.max_mtu : RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
    int large = (uint32_t)config->mtu + overhead > config->mbuf_data_size;
    if (large) {
        *stage = NTCP_STAGE_SCATTER;
        if (!(info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER)) return -ENOTSUP;
        rx |= RTE_ETH_RX_OFFLOAD_SCATTER;
    }
    // The adapter chains any frame longer than one mbuf, and explicit zero-copy
    // needs chains: enable multi-segment TX whenever supported, require it
    // when MTU-sized frames cannot fit one mbuf.
    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
        tx |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    } else if (large) {
        *stage = NTCP_STAGE_MULTI_SEGS;
        return -ENOTSUP;
    }
    // TCP segmentation, when requested and the device offers it with the
    // checksum offloads that fill each segment's checksums
    // (ntcp_dpdk_tso_gate). Only mbufs that ask for them, by their ol_flags
    // (ntcp_dpdk_tso_transmit), are segmented or checksummed.
    const uint64_t segmentation = RTE_ETH_TX_OFFLOAD_TCP_TSO |
        RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    *tcp_segmentation = config->tcp_segmentation &&
        (info.tx_offload_capa & segmentation) == segmentation;
    if (*tcp_segmentation) tx |= segmentation;
    // TCP checksum verification on RX whenever the device offers it and the
    // host asks (checksum_offload): its verdict (RTE_MBUF_F_RX_L4_CKSUM_*)
    // spares the stack verifying a good checksum, as Linux enables rx
    // checksumming by default. Bit 0 of *checksums reports it.
    *checksums = 0;
    if (config->checksum_offload && (info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)) {
        rx |= RTE_ETH_RX_OFFLOAD_TCP_CKSUM;
        *checksums |= 1;
    }
    // And on TX, bit 1: the device completes the TCP checksum of each
    // segment that asks for it by its ol_flags (ntcp_dpdk_transmit).
    if (config->checksum_offload && (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)) {
        tx |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
        *checksums |= 2;
    }
    // Without RSS a queue receives only what flows steer to it (or queue 0's
    // default traffic), so each worker sees exactly its own connections. With
    // RSS, unsteered traffic is spread by the device's hash and redirection
    // table, which the caller reads back (ntcp_dpdk_rss_query) to know where
    // each flow lands. The algorithm stays the PMD default (mlx5: Toeplitz).
    struct rte_eth_conf conf = {0};
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    *key_size = info.hash_key_size;
    // A key is checked even with one queue, where it goes unused, so that a
    // wrong one never passes silently.
    *stage = NTCP_STAGE_RSS_KEY;
    if (config->rss_key && config->rss_key_len != info.hash_key_size) return -EINVAL;
    if (config->rss && config->queues > 1) {
        *stage = NTCP_STAGE_RSS;
        uint64_t hf = ntcp_rss_hf & info.flow_type_rss_offloads;
        if (!hf) return -ENOTSUP;
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        conf.rx_adv_conf.rss_conf.rss_hf = hf;
        // NULL leaves the key to the PMD. ethdev keeps this pointer in the
        // device configuration and some PMDs read it again at start.
        conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)config->rss_key;
        conf.rx_adv_conf.rss_conf.rss_key_len = config->rss_key ? config->rss_key_len : 0;
    }
    conf.rxmode.mtu = config->mtu;
    conf.rxmode.offloads = rx;
    conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    conf.txmode.offloads = tx;
    *stage = NTCP_STAGE_CONFIGURE;
    result = rte_eth_dev_configure(port, config->queues, config->queues, &conf);
    if (result < 0) return result;
    *stage = NTCP_STAGE_DESCRIPTORS;
    *rx_desc = config->rx_desc;
    *tx_desc = config->tx_desc;
    return rte_eth_dev_adjust_nb_rx_tx_desc(port, rx_desc, tx_desc);
}

// Queue offloads stay zero: port-level offloads already apply to every queue.
int ntcp_dpdk_port_queue_setup(uint16_t port, uint16_t queue, uint16_t rx_desc,
                               uint16_t tx_desc, int socket, void *pool) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    struct rte_eth_rxconf rxconf = info.default_rxconf;
    rxconf.offloads = 0;
    result = rte_eth_rx_queue_setup(port, queue, rx_desc, socket, &rxconf, pool);
    if (result < 0) return result;
    struct rte_eth_txconf txconf = info.default_txconf;
    txconf.offloads = 0;
    return rte_eth_tx_queue_setup(port, queue, tx_desc, socket, &txconf);
}

int ntcp_dpdk_port_start(uint16_t port) { return rte_eth_dev_start(port); }

// The port's receive buffer shortage (rte_eth_stats rx_nombuf, imissed).
// ethdev control calls are not thread-safe: the caller serializes them per
// port (mlx5 updates its imissed wrap state here).
int ntcp_dpdk_port_stats(uint16_t port, uint64_t *rx_nombuf, uint64_t *imissed) {
    struct rte_eth_stats stats;
    int result = rte_eth_stats_get(port, &stats);
    if (result < 0) return result;
    *rx_nombuf = stats.rx_nombuf;
    *imissed = stats.imissed;
    return 0;
}

// Teardown after every queue user and flow is gone: stop, close (releases the
// port), drop ownership, and detach the device once it has no ethdev port
// left, so a later claim can probe it again. Best effort; nothing to report.
void ntcp_dpdk_port_release(uint16_t port, uint64_t owner, int started) {
    struct rte_eth_dev_info info;
    struct rte_device *device = rte_eth_dev_info_get(port, &info) == 0 ? info.device : NULL;
    if (started) rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    rte_eth_dev_owner_delete(owner);
    if (device && rte_eth_find_next_of(0, device) == RTE_MAX_ETHPORTS)
        rte_dev_remove(device);
}

int ntcp_dpdk_read_clock(uint16_t port, uint64_t *clock) {
    return rte_eth_read_clock(port, clock);
}

// The default (index 0) address, as the device reports it now. Copied out
// as bytes: Rust does not mirror struct rte_ether_addr.
int ntcp_dpdk_port_mac(uint16_t port, uint8_t mac[6]) {
    struct rte_ether_addr address;
    int result = rte_eth_macaddr_get(port, &address);
    if (result < 0) return result;
    memcpy(mac, address.addr_bytes, RTE_ETHER_ADDR_LEN);
    return 0;
}

// The ethdev driver name (dev_info.driver_name), NUL-terminated within
// capacity.
int ntcp_dpdk_port_driver(uint16_t port, char *name, size_t capacity) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    snprintf(name, capacity, "%s", info.driver_name ? info.driver_name : "");
    return 0;
}

// ETH / IPV4 (exact destination[, protocol]) [/ TCP or UDP, any header] ->
// QUEUE at priority. dst is in network byte order; l4 is 0 (no L4 item),
// IPPROTO_TCP or IPPROTO_UDP; proto is 0 (any) or l4, matched as the IPv4
// next_proto_id under a full mask. ixgbe ignores an L4 item without spec
// and mask, so only proto tells its rules apart (cons_parse_ntuple_filter).
// With flow NULL the rule is only validated, otherwise created into *flow.
// Returns 0 or a negative errno; on failure *priority_refused tells whether
// the PMD refused the priority attribute (RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY).
int ntcp_dpdk_flow_ipv4(uint16_t port, uint32_t dst, uint8_t l4, uint8_t proto,
                        uint32_t priority, uint16_t queue, void **flow,
                        int *priority_refused, char *message, size_t capacity) {
    if (l4 != 0 && l4 != IPPROTO_TCP && l4 != IPPROTO_UDP) return -EINVAL;
    if (proto != 0 && proto != l4) return -EINVAL;
    struct rte_flow_attr attr = { .ingress = 1, .priority = priority };
    struct rte_flow_item_ipv4 spec = {0}, mask = {0};
    spec.hdr.dst_addr = dst;
    mask.hdr.dst_addr = UINT32_MAX;
    spec.hdr.next_proto_id = proto;
    mask.hdr.next_proto_id = proto ? UINT8_MAX : 0;
    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &spec, .mask = &mask },
        { .type = l4 == IPPROTO_TCP   ? RTE_FLOW_ITEM_TYPE_TCP
                  : l4 == IPPROTO_UDP ? RTE_FLOW_ITEM_TYPE_UDP
                                      : RTE_FLOW_ITEM_TYPE_END },
        { .type = RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action_queue target = { .index = queue };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &target },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_error flow_error = {0};
    int result;
    if (flow) {
        *flow = rte_flow_create(port, &attr, pattern, actions, &flow_error);
        result = *flow ? 0 : -rte_errno;
    } else {
        result = rte_flow_validate(port, &attr, pattern, actions, &flow_error);
    }
    *priority_refused = result < 0 && flow_error.type == RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY;
    if (result < 0) flow_message(&flow_error, message, capacity);
    return result;
}

// ETH / IPV4 (exact destination) / TCP (destination port under mask) ->
// QUEUE. dst and dst_port are in network byte order, mask in host order.
// Validated first, so a PMD that cannot match this pattern refuses it before
// anything is installed (stage 1); stage 2 is the creation itself. Priority
// 0, ahead of the address rules Port::steer_ipv4 installs at 1 where the PMD
// takes priorities (at 0 where it refuses them, and rte_flow leaves the
// overlap undefined).
void *ntcp_dpdk_flow_tcp_port(uint16_t port, uint32_t dst, uint16_t dst_port,
                              uint16_t mask, uint16_t queue, int *error, int *stage,
                              char *message, size_t capacity) {
    struct rte_flow_attr attr = { .ingress = 1 };
    struct rte_flow_item_ipv4 ip_spec = {0}, ip_mask = {0};
    ip_spec.hdr.dst_addr = dst;
    ip_mask.hdr.dst_addr = UINT32_MAX;
    struct rte_flow_item_tcp tcp_spec = {0}, tcp_mask = {0};
    tcp_spec.hdr.dst_port = dst_port;
    tcp_mask.hdr.dst_port = rte_cpu_to_be_16(mask);
    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask },
        { .type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_spec, .mask = &tcp_mask },
        { .type = RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action_queue target = { .index = queue };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &target },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_error flow_error = {0};
    *stage = 1;
    int result = rte_flow_validate(port, &attr, pattern, actions, &flow_error);
    if (result < 0) {
        *error = result;
        flow_message(&flow_error, message, capacity);
        return NULL;
    }
    *stage = 2;
    struct rte_flow *flow = rte_flow_create(port, &attr, pattern, actions, &flow_error);
    *error = flow ? 0 : -rte_errno;
    if (!flow) flow_message(&flow_error, message, capacity);
    return flow;
}

int ntcp_dpdk_flow_destroy(uint16_t port, void *flow) {
    struct rte_flow_error error;
    return rte_flow_destroy(port, flow, &error);
}

int ntcp_dpdk_rss_sizes(uint16_t port, uint16_t *key_size, uint16_t *reta_size) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    *key_size = info.hash_key_size;
    *reta_size = info.reta_size;
    return 0;
}

enum { NTCP_RSS_IPV4_TCP = 1, NTCP_RSS_IPV4 = 2, NTCP_RSS_FRAG_IPV4 = 4 };

// The hash function is passed to Rust as DPDK's value; host.rs names these.
_Static_assert(RTE_ETH_HASH_FUNCTION_DEFAULT == 0 && RTE_ETH_HASH_FUNCTION_TOEPLITZ == 1 &&
    RTE_ETH_HASH_FUNCTION_SIMPLE_XOR == 2 && RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ == 3 &&
    RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ_SORT == 4, "hash function values changed");

static struct rte_eth_rss_reta_entry64 *reta_groups(uint16_t length) {
    size_t groups = (length + RTE_ETH_RETA_GROUP_SIZE - 1) / RTE_ETH_RETA_GROUP_SIZE;
    struct rte_eth_rss_reta_entry64 *table = calloc(groups, sizeof(*table));
    if (!table) return NULL;
    for (uint16_t i = 0; i < length; ++i)
        table[i / RTE_ETH_RETA_GROUP_SIZE].mask |= UINT64_C(1) << (i % RTE_ETH_RETA_GROUP_SIZE);
    return table;
}

// The key, granted hash types, hash function and the whole redirection
// table in effect. Returns -ENOSPC (sizes set) if a buffer is smaller than
// the device's, and -ENOTSUP if the device reports no key or no table.
// ethdev presets the function to DEFAULT, which a PMD that does not report
// it (mlx5) leaves.
int ntcp_dpdk_rss_query(uint16_t port, uint8_t *key, uint16_t key_capacity,
                        uint16_t *reta, uint16_t reta_capacity, uint16_t *key_len,
                        uint16_t *reta_len, uint8_t *hash, uint32_t *algorithm) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    *key_len = info.hash_key_size;
    *reta_len = info.reta_size;
    if (!info.hash_key_size || !info.reta_size) return -ENOTSUP;
    if (info.hash_key_size > key_capacity || info.reta_size > reta_capacity) return -ENOSPC;
    struct rte_eth_rss_conf conf = { .rss_key = key, .rss_key_len = info.hash_key_size };
    result = rte_eth_dev_rss_hash_conf_get(port, &conf);
    if (result < 0) return result;
    // Some PMDs report the key length they used, others leave it as passed.
    if (!conf.rss_key_len || conf.rss_key_len > info.hash_key_size) return -EIO;
    *key_len = conf.rss_key_len;
    *algorithm = (uint32_t)conf.algorithm;
    *hash = (conf.rss_hf & RTE_ETH_RSS_NONFRAG_IPV4_TCP ? NTCP_RSS_IPV4_TCP : 0) |
        (conf.rss_hf & RTE_ETH_RSS_IPV4 ? NTCP_RSS_IPV4 : 0) |
        (conf.rss_hf & RTE_ETH_RSS_FRAG_IPV4 ? NTCP_RSS_FRAG_IPV4 : 0);
    struct rte_eth_rss_reta_entry64 *table = reta_groups(info.reta_size);
    if (!table) return -ENOMEM;
    result = rte_eth_dev_rss_reta_query(port, table, info.reta_size);
    if (result == 0)
        for (uint16_t i = 0; i < info.reta_size; ++i)
            reta[i] = table[i / RTE_ETH_RETA_GROUP_SIZE].reta[i % RTE_ETH_RETA_GROUP_SIZE];
    free(table);
    return result;
}

// Replaces every entry; ethdev checks each against the RX queue count.
int ntcp_dpdk_rss_reta_update(uint16_t port, const uint16_t *reta, uint16_t length) {
    struct rte_eth_rss_reta_entry64 *table = reta_groups(length);
    if (!table) return -ENOMEM;
    for (uint16_t i = 0; i < length; ++i)
        table[i / RTE_ETH_RETA_GROUP_SIZE].reta[i % RTE_ETH_RETA_GROUP_SIZE] = reta[i];
    int result = rte_eth_dev_rss_reta_update(port, table, length);
    free(table);
    return result;
}
