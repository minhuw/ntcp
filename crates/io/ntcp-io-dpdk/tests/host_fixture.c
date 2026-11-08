#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mempool.h>

// Independent observations for tests/host_pmd.rs; the host module under test
// never calls these.
int ntcp_host_test_cpu(void) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus)) return -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
        if (CPU_ISSET(cpu, &cpus)) return cpu;
    return -1;
}

struct pool_count { unsigned pools, full; };
static void count_pool(struct rte_mempool *pool, void *arg) {
    struct pool_count *count = arg;
    if (strncmp(pool->name, "ntcp_p", 6)) return;
    count->pools++;
    if (rte_mempool_full(pool)) count->full++;
}
unsigned ntcp_host_test_pools(unsigned *full) {
    struct pool_count count = {0};
    rte_mempool_walk(count_pool, &count);
    *full = count.full;
    return count.pools;
}

unsigned ntcp_host_test_lcore(void) { return rte_lcore_id(); }

int ntcp_host_test_port_named(const char *name) {
    uint16_t port;
    return rte_eth_dev_get_port_by_name(name, &port) == 0 ? port : -1;
}

// Reads and sets the default MAC through ethdev's own calls, beside the
// host module's shim.
int ntcp_host_test_mac(uint16_t port, uint8_t mac[6]) {
    struct rte_ether_addr address;
    int result = rte_eth_macaddr_get(port, &address);
    if (result == 0) memcpy(mac, address.addr_bytes, RTE_ETHER_ADDR_LEN);
    return result;
}
int ntcp_host_test_set_mac(uint16_t port, const uint8_t mac[6]) {
    struct rte_ether_addr address;
    memcpy(address.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    return rte_eth_dev_default_mac_addr_set(port, &address);
}

// Keeps the ring PMD, and with it the net_ring vdev driver, linked even
// under --as-needed when no other object references it.
void *ntcp_host_test_ring_driver(void) { return (void *)rte_eth_from_rings; }
