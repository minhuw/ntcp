#ifndef NTCP_DPDK_SHIM_H
#define NTCP_DPDK_SHIM_H
#include <stddef.h>
#include <stdint.h>
#define NTCP_DPDK_MAX_PACKET_LEN 65535u
int ntcp_dpdk_valid_port(uint16_t port);
int ntcp_dpdk_receive(uint16_t port, uint16_t queue, uint8_t *out,
                      size_t capacity, size_t *length);
int ntcp_dpdk_transmit(uint16_t port, uint16_t queue, void *pool,
                       const uint8_t *packet, size_t length);
#endif
