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
