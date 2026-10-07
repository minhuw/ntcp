#include "shim.h"
#include <errno.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

int ntcp_dpdk_valid_port(uint16_t port) {
    return rte_eth_dev_is_valid_port(port);
}

int ntcp_dpdk_receive(uint16_t port, uint16_t queue, uint8_t *out,
                      size_t capacity, size_t *length) {
    struct rte_mbuf *m;
    *length = 0;
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
