#ifndef NTCP_DPDK_SHIM_H
#define NTCP_DPDK_SHIM_H
#include <stddef.h>
#include <stdint.h>
#define NTCP_DPDK_MAX_PACKET_LEN 65535u
int ntcp_dpdk_get_mtu(uint16_t port, uint16_t *mtu);
int ntcp_dpdk_valid_port(uint16_t port);
int ntcp_dpdk_tx_timestamp_lookup(int *offset, uint64_t *flag);
int ntcp_dpdk_tx_scheduling_check(uint16_t port, uint16_t queue);
int ntcp_dpdk_rx_timestamp_lookup(int *offset, uint64_t *flag);
int ntcp_dpdk_rx_timestamp_status(uint16_t port, uint16_t queue,
                                   int *supported, int *enabled);
int ntcp_dpdk_receive(uint16_t port, uint16_t queue, uint8_t *out,
                      size_t capacity, size_t *length, int timestamp_offset,
                      uint64_t timestamp_flag, uint64_t *timestamp, int *timestamp_valid);
int ntcp_dpdk_transmit(uint16_t port, uint16_t queue, void *pool,
                       const uint8_t *packet, size_t length, int timestamp_offset,
                       uint64_t timestamp_flag, uint64_t timestamp);
struct ntcp_tso_config { uint16_t mtu, room, max_descriptors; };
int ntcp_dpdk_tso_check(uint16_t port, uint16_t queue, void *pool, struct ntcp_tso_config *config);
int ntcp_dpdk_tso_transmit(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *packet, size_t length, uint16_t l3, uint16_t mss,
    const struct ntcp_tso_config *config);

struct ntcp_shared_segment {
    const void *address;
    uint64_t iova;
    uint16_t length;
    void *lease;
};
typedef void (*ntcp_release_fn)(void *);
void *ntcp_dpdk_payload_alloc(size_t length, uint64_t *iova);
void ntcp_dpdk_payload_free(void *address);
int ntcp_dpdk_reclaim(uint16_t port, uint16_t queue, uint32_t budget);
int ntcp_dpdk_shared_check(uint16_t port, uint16_t queue, void *pool, uint16_t *limit);
// Takes every lease, including on rejection or allocation failure.
int ntcp_dpdk_shared_transmit(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, uint16_t header_length,
    const struct ntcp_shared_segment *segments, uint16_t count,
    ntcp_release_fn release);

#endif
