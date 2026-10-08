#include "shim.h"
#include <errno.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_errno.h>

int ntcp_dpdk_valid_port(uint16_t port) {
    return rte_eth_dev_is_valid_port(port);
}

// Host/PMD registers the standard field/flag during setup. Look up once per
// adapter, never register or reconfigure a live device on the packet path.
int ntcp_dpdk_rx_timestamp_lookup(int *offset, uint64_t *flag) {
    struct rte_mbuf_dynfield field;
    int off = rte_mbuf_dynfield_lookup(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, &field);
    if (off < 0) return -rte_errno;
    if (field.size != sizeof(rte_mbuf_timestamp_t) ||
        field.align != _Alignof(rte_mbuf_timestamp_t) || field.flags != 0)
        return -EINVAL;
    struct rte_mbuf_dynflag dynflag;
    int bit = rte_mbuf_dynflag_lookup(RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, &dynflag);
    if (bit < 0) return -rte_errno;
    if (bit >= 64 || dynflag.flags != 0) return -EINVAL;
    *offset = off;
    *flag = UINT64_C(1) << bit;
    return 0;
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
                       const uint8_t *packet, size_t length) {
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
    if (rte_eth_tx_burst(port, queue, &head, 1) == 1)
        return 1; // Driver owns it; never free a submitted mbuf here.
    rte_pktmbuf_free(head);
    return 0;
}
