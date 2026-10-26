#define ALLOW_EXPERIMENTAL_API // DPDK 23.11 read-only rte_eth_dev_conf_get.
#include "shim.h"
#include <errno.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
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

int ntcp_dpdk_receive(uint16_t port, uint16_t queue, uint8_t *out,
                      size_t capacity, size_t *length, int timestamp_offset,
                      uint64_t timestamp_flag, uint64_t *timestamp, int *timestamp_valid) {
    struct rte_mbuf *m;
    *length = 0;
    *timestamp = 0;
    *timestamp_valid = 0;
    // ponytail: burst one; batch only if profiling shows call overhead matters.
    if (rte_eth_rx_burst(port, queue, &m, 1) == 0)
        return 0;
    // PacketIo carries bytes only: stripped tags and coalesced packets cannot
    // be reconstructed from offload metadata without changing its contract.
    int result = -ENOTSUP;
    if (m->ol_flags & (RTE_MBUF_F_RX_VLAN_STRIPPED |
                       RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_LRO))
        goto done;
    result = -EMSGSIZE;
    size_t total = m->pkt_len;
    if (total > NTCP_DPDK_MAX_PACKET_LEN || total > capacity)
        goto done;
    // Validate the entire chain before writing any caller bytes.
    size_t sum = 0;
    struct rte_mbuf *segment = m;
    result = -EIO;
    for (uint32_t i = 0; i < m->nb_segs; ++i) {
        if (!segment || segment->data_off > segment->buf_len ||
            segment->data_len > segment->buf_len - segment->data_off ||
            segment->data_len > total - sum)
            goto done;
        sum += segment->data_len;
        segment = segment->next;
    }
    if (segment || !m->nb_segs || sum != total)
        goto done;
    size_t offset = 0;
    for (segment = m; segment; segment = segment->next) {
        memcpy(out + offset, rte_pktmbuf_mtod(segment, const void *), segment->data_len);
        offset += segment->data_len;
    }
    if (timestamp_offset >= 0 && (m->ol_flags & timestamp_flag)) {
        *timestamp = *RTE_MBUF_DYNFIELD(m, timestamp_offset, rte_mbuf_timestamp_t *);
        *timestamp_valid = 1;
    }
    *length = total;
    result = 1;
done:
    // RX dequeue transferred this entire chain to us, even on rejection.
    rte_pktmbuf_free(m);
    return result;
}

int ntcp_dpdk_transmit(uint16_t port, uint16_t queue, void *pool,
                       const uint8_t *packet, size_t length, int timestamp_offset,
                       uint64_t timestamp_flag, uint64_t timestamp) {
    if (!length)
        return -EINVAL;
    if (length > NTCP_DPDK_MAX_PACKET_LEN)
        return -EMSGSIZE;
    struct rte_mbuf *head = NULL, *tail = NULL;
    size_t offset = 0;
    while (offset < length) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        if (!m) {
            rte_pktmbuf_free(head);
            return 0;
        }
        size_t chunk = rte_pktmbuf_tailroom(m);
        if (!chunk) {
            rte_pktmbuf_free(m);
            rte_pktmbuf_free(head);
            return -EINVAL;
        }
        if (chunk > length - offset)
            chunk = length - offset;
        void *dst = rte_pktmbuf_append(m, (uint16_t)chunk);
        memcpy(dst, packet + offset, chunk);
        // Newly allocated mbufs request no checksum or segmentation offloads.
        if (!head) {
            head = m;
        } else {
            tail->next = m;
            head->nb_segs++;
            head->pkt_len += (uint32_t)chunk;
        }
        tail = m;
        offset += chunk;
    }
    if (timestamp_offset >= 0) {
        *RTE_MBUF_DYNFIELD(head, timestamp_offset, rte_mbuf_timestamp_t *) = timestamp;
        head->ol_flags |= timestamp_flag;
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
    if ((l3 != 20 && l3 != 40) || !mss || !config->room ||
        length <= 14u + l3 + 20u || length > NTCP_DPDK_MAX_PACKET_LEN ||
        config->room < 14u + l3 + 20u ||
        (length + config->room - 1) / config->room > config->max_descriptors)
        return -EINVAL;
    struct rte_mbuf *head = NULL, *tail = NULL;
    size_t offset = 0;
    while (offset < length) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        if (!m) { rte_pktmbuf_free(head); return 0; }
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
    head->l4_len = 20;
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

void *ntcp_dpdk_payload_alloc(size_t length, uint64_t *iova) {
    if (!length || length > NTCP_DPDK_MAX_PACKET_LEN) return NULL;
    void *p = rte_zmalloc(NULL, length, RTE_CACHE_LINE_SIZE);
    if (!p) return NULL;
    rte_iova_t base = rte_mem_virt2iova(p);
    // The external mbuf describes one contiguous IOVA span. Refuse fragmented
    // mappings rather than assuming that virtually contiguous implies DMA-safe.
    if (base == RTE_BAD_IOVA) { rte_free(p); return NULL; }
    for (size_t offset = 0; offset < length;) {
        const char *at = (const char *)p + offset;
        const struct rte_memseg *ms = rte_mem_virt2memseg(at, NULL);
        if (!ms || rte_mem_virt2iova(at) != base + offset) {
            rte_free(p); return NULL;
        }
        size_t left = (uintptr_t)ms->addr + ms->len - (uintptr_t)at;
        if (!left) { rte_free(p); return NULL; }
        offset += RTE_MIN(left, length - offset);
    }
    *iova = base;
    return p;
}
void ntcp_dpdk_payload_free(void *address) { rte_free(address); }

int ntcp_dpdk_reclaim(uint16_t port, uint16_t queue, uint32_t budget) {
    if (!budget) return 0; // DPDK zero means unbounded: never forward it.
    return rte_eth_tx_done_cleanup(port, queue, budget);
}
int ntcp_dpdk_shared_check(uint16_t port, uint16_t queue, void *pool, uint16_t *limit) {
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result < 0) return result;
    if (queue >= info.nb_tx_queues) return -EINVAL;
    struct rte_eth_conf conf;
    result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    struct rte_eth_txq_info qinfo;
    result = rte_eth_tx_queue_info_get(port, queue, &qinfo);
    if (result < 0) return result;
    if (!(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) ||
        !((conf.txmode.offloads | qinfo.conf.offloads) & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) ||
        !info.tx_desc_lim.nb_seg_max || !info.tx_desc_lim.nb_mtu_seg_max || !qinfo.nb_desc ||
        ((conf.txmode.offloads | qinfo.conf.offloads) & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) ||
        rte_pktmbuf_data_room_size(pool) < RTE_PKTMBUF_HEADROOM + 134)
        return -ENOTSUP;
    *limit = RTE_MIN(RTE_MIN(info.tx_desc_lim.nb_seg_max,
                          info.tx_desc_lim.nb_mtu_seg_max), qinfo.nb_desc);
    if (*limit < 3) return -ENOTSUP;
    // Idle TX must progress without waiting for another packet to be sent.
    // This may reclaim a completed packet but never changes port settings.
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
    result = 0;
    head = rte_pktmbuf_alloc(pool);
    if (!head) goto done;
    void *dst = rte_pktmbuf_append(head, header_length);
    if (!dst) { result = -EINVAL; goto done; }
    memcpy(dst, header, header_length);
    for (; consumed < count;) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
        struct ntcp_external *e = calloc(1, sizeof(*e));
        if (!m || !e) { rte_pktmbuf_free(m); free(e); goto done; }
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
    if (rte_eth_tx_burst(port, queue, &head, 1) == 1) {
        head = NULL;
        result = 1;
    }
done:
    rte_pktmbuf_free(head);
    for (; consumed < count; ++consumed) release(segments[consumed].lease);
    return result;
}
