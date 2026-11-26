#ifndef NTCP_DPDK_SHIM_H
#define NTCP_DPDK_SHIM_H
#include <stddef.h>
#include <stdint.h>
#define NTCP_DPDK_MAX_PACKET_LEN 65535u
// The transmit calls return 1 when the PMD took the packet, 0 when its TX
// ring did not (or, shared, a heap allocation failed), NTCP_DPDK_NOMBUF when
// the pool had no mbuf for it, and a negative errno when the packet was
// refused. Nothing is kept on 0 or NTCP_DPDK_NOMBUF: the caller may retry.
#define NTCP_DPDK_NOMBUF 2
// ntcp_dpdk_receive_meta: the mbuf is to be copied, not held.
#define NTCP_DPDK_COPY 2
int ntcp_dpdk_get_mtu(uint16_t port, uint16_t *mtu);
int ntcp_dpdk_valid_port(uint16_t port);
int ntcp_dpdk_tx_timestamp_lookup(int *offset, uint64_t *flag);
int ntcp_dpdk_tx_scheduling_check(uint16_t port, uint16_t queue);
int ntcp_dpdk_rx_timestamp_lookup(int *offset, uint64_t *flag);
int ntcp_dpdk_rx_timestamp_status(uint16_t port, uint16_t queue,
                                   int *supported, int *enabled);
struct rte_mbuf;
struct ntcp_rx_view {
    void *data;
    uint16_t length;
    uint8_t l4_status;
};
uint16_t ntcp_dpdk_receive_burst(uint16_t port, uint16_t queue,
                                 struct rte_mbuf **packets, uint16_t count,
                                 const void *pool, int l4_checksum,
                                 struct ntcp_rx_view *views);
void ntcp_dpdk_packet_free(void *packet);
void ntcp_dpdk_frame_free(void *packet);
int ntcp_dpdk_rx_checksum_check(uint16_t port, uint16_t queue);
int ntcp_dpdk_receive(void *packet, uint8_t *out,
                      size_t capacity, size_t *length, int timestamp_offset,
                      uint64_t timestamp_flag, uint64_t *timestamp, int *timestamp_valid,
                      int l4_checksum, int *l4_status);
struct ntcp_rx_meta {
    void *data;
    uint64_t timestamp;
    int timestamp_valid, l4_status;
    uint16_t length;
};
int ntcp_dpdk_receive_meta(void *packet, const void *pool, int timestamp_offset,
                           uint64_t timestamp_flag, int l4_checksum,
                           struct ntcp_rx_meta *out);
void ntcp_dpdk_pool_geometry(const void *pool, uint32_t *element, uint32_t *cache,
                             uint32_t *size);
uint16_t ntcp_dpdk_pool_room(const void *pool);
int ntcp_dpdk_tx_checksum_check(uint16_t port, uint16_t queue);
int ntcp_dpdk_transmit(uint16_t port, uint16_t queue, void *pool,
                       const uint8_t *packet, size_t length, int timestamp_offset,
                       uint64_t timestamp_flag, uint64_t timestamp, uint16_t l3);
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
int ntcp_dpdk_shared_check(uint16_t port, uint16_t queue, void *pool, uint16_t *limit,
                           int *stage);
// Takes every lease, including on rejection or allocation failure.
int ntcp_dpdk_shared_transmit(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, uint16_t header_length,
    const struct ntcp_shared_segment *segments, uint16_t count,
    ntcp_release_fn release);

typedef void (*ntcp_chunk_free_fn)(void *chunk, void *recycler);
void *ntcp_dpdk_chunk_alloc(size_t capacity, void *recycler,
                            ntcp_chunk_free_fn recycle_cb, uint8_t **data_out);
void ntcp_dpdk_chunk_reset(void *chunk, void *recycler, uint8_t **data_out);
void ntcp_dpdk_chunk_release(void *chunk);
void ntcp_dpdk_chunk_free(void *chunk);
uint16_t ntcp_dpdk_chunk_refcnt(const void *chunk);

struct ntcp_tx_offload {
    int timestamp_offset;
    uint64_t timestamp_flag;
    uint64_t timestamp;
    uint16_t l3;
    uint16_t l4;
    uint16_t mss;
};

enum {
    NTCP_EXT_CHUNK = 0,
    NTCP_EXT_SHARED = 1,
};

struct ntcp_ext_part {
    uint8_t kind;
    uint16_t length;
    uint32_t offset;
    void *handle;
    const void *address;
    uint64_t iova;
};

struct ntcp_copy_part {
    const uint8_t *ptr;
    size_t length;
};

// Takes every NTCP_EXT_SHARED lease, including on rejection or allocation
// failure. NTCP_EXT_CHUNK entries bump the chunk's embedded extbuf refcnt
// without per-packet heap allocation.
int ntcp_dpdk_packet_transmit_ext(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, uint16_t header_length,
    const struct ntcp_ext_part *parts, uint16_t count,
    ntcp_release_fn shared_release,
    const struct ntcp_tx_offload *offload);

int ntcp_dpdk_packet_transmit_copy(uint16_t port, uint16_t queue, void *pool,
    const uint8_t *header, size_t header_length,
    const struct ntcp_copy_part *parts, size_t count,
    const struct ntcp_tx_offload *offload,
    uint16_t max_descriptors);

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
    uint8_t rx_timestamps, rss, rss_key_len, tcp_segmentation, checksum_offload;
    // Must stay valid until the port is closed: ethdev keeps the pointer.
    const uint8_t *rss_key;
};
int ntcp_dpdk_port_configure(uint16_t port, const struct ntcp_port_config *config,
                             uint16_t *rx_desc, uint16_t *tx_desc, int *stage,
                             uint8_t *key_size, uint8_t *tcp_segmentation,
                             uint8_t *checksums);
int ntcp_dpdk_port_queue_setup(uint16_t port, uint16_t queue, uint16_t rx_desc,
                               uint16_t tx_desc, int socket, void *pool);
int ntcp_dpdk_port_start(uint16_t port);
int ntcp_dpdk_port_stats(uint16_t port, uint64_t *rx_nombuf, uint64_t *imissed);
void ntcp_dpdk_port_release(uint16_t port, uint64_t owner, int started);
int ntcp_dpdk_read_clock(uint16_t port, uint64_t *clock);
int ntcp_dpdk_port_mac(uint16_t port, uint8_t mac[6]);
int ntcp_dpdk_port_driver(uint16_t port, char *name, size_t capacity);
int ntcp_dpdk_flow_ipv4(uint16_t port, uint32_t dst, uint8_t l4, uint32_t priority,
                        uint16_t queue, void **flow, int *priority_refused, char *message,
                        size_t capacity);
void *ntcp_dpdk_flow_tcp_port(uint16_t port, uint32_t dst, uint16_t dst_port,
                              uint16_t mask, uint16_t queue, int *error, int *stage,
                              char *message, size_t capacity);
int ntcp_dpdk_flow_destroy(uint16_t port, void *flow);
int ntcp_dpdk_rss_sizes(uint16_t port, uint16_t *key_size, uint16_t *reta_size);
int ntcp_dpdk_rss_query(uint16_t port, uint8_t *key, uint16_t key_capacity,
                        uint16_t *reta, uint16_t reta_capacity, uint16_t *key_len,
                        uint16_t *reta_len, uint8_t *hash, uint32_t *algorithm);
int ntcp_dpdk_rss_reta_update(uint16_t port, const uint16_t *reta, uint16_t length);

#endif
