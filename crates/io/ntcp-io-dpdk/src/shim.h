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
struct rte_mbuf;
uint16_t ntcp_dpdk_receive_burst(uint16_t port, uint16_t queue,
                                  struct rte_mbuf **packets, uint16_t count);
void ntcp_dpdk_packet_free(void *packet);
int ntcp_dpdk_receive(void *packet, uint8_t *out,
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

// Host setup: owns EAL, ports, pools and flows (see host.rs for ordering).
int ntcp_dpdk_eal_init(int argc, char **argv);
unsigned ntcp_dpdk_main_lcore(void);
unsigned ntcp_dpdk_lcore_id(void);
int ntcp_dpdk_thread_register(void);
void ntcp_dpdk_thread_unregister(void);
int ntcp_dpdk_port_claim(const char *devargs, uint64_t *owner, uint16_t *port);
int ntcp_dpdk_port_isolate(uint16_t port, char *message, size_t capacity);
int ntcp_dpdk_port_socket(uint16_t port);
void *ntcp_dpdk_pool_create(const char *name, uint32_t count, uint16_t data_size,
                            int socket, int *error);
int ntcp_dpdk_pool_free(void *pool);
struct ntcp_port_config {
    uint16_t queues, rx_desc, tx_desc, mtu, mbuf_data_size;
    uint8_t rx_timestamps;
};
int ntcp_dpdk_port_configure(uint16_t port, const struct ntcp_port_config *config,
                             uint16_t *rx_desc, uint16_t *tx_desc, int *stage);
int ntcp_dpdk_port_queue_setup(uint16_t port, uint16_t queue, uint16_t rx_desc,
                               uint16_t tx_desc, int socket, void *pool);
int ntcp_dpdk_port_start(uint16_t port);
void ntcp_dpdk_port_release(uint16_t port, uint64_t owner, int started);
int ntcp_dpdk_read_clock(uint16_t port, uint64_t *clock);
void *ntcp_dpdk_flow_ipv4(uint16_t port, uint32_t dst, uint16_t queue, int *error,
                          char *message, size_t capacity);
int ntcp_dpdk_flow_destroy(uint16_t port, void *flow);

#endif
