#define _GNU_SOURCE
#define ALLOW_EXPERIMENTAL_API // rte_eth_dev_conf_get.
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

// The RSS part of the configuration ethdev holds for the port, as the host
// module passed it: whether mq_mode is RSS, the hash types, and the key
// (key_len 0 if the PMD was left to choose).
int ntcp_host_test_rss_conf(uint16_t port, int *rss, uint64_t *hf, uint8_t key[255],
                            uint8_t *key_len) {
    struct rte_eth_conf conf;
    int result = rte_eth_dev_conf_get(port, &conf);
    if (result < 0) return result;
    *rss = conf.rxmode.mq_mode == RTE_ETH_MQ_RX_RSS;
    *hf = conf.rx_adv_conf.rss_conf.rss_hf;
    *key_len = conf.rx_adv_conf.rss_conf.rss_key ? conf.rx_adv_conf.rss_conf.rss_key_len : 0;
    if (*key_len) memcpy(key, conf.rx_adv_conf.rss_conf.rss_key, *key_len);
    return 0;
}
uint64_t ntcp_host_test_rss_ipv4_hf(void) {
    return RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4;
}

// The device's key, hash function and redirection table, read with
// ethdev's own calls. The function is reported as 1 for Toeplitz, 0 for the
// PMD's unreported default and 2 for any other.
int ntcp_host_test_rss_key(uint16_t port, uint8_t key[255], uint8_t *key_len,
                           int *algorithm) {
    struct rte_eth_rss_conf conf = { .rss_key = key, .rss_key_len = 255 };
    int result = rte_eth_dev_rss_hash_conf_get(port, &conf);
    struct rte_eth_dev_info info;
    if (result == 0) result = rte_eth_dev_info_get(port, &info);
    if (result == 0) *key_len = info.hash_key_size;
    *algorithm = conf.algorithm == RTE_ETH_HASH_FUNCTION_TOEPLITZ ? 1 :
        conf.algorithm == RTE_ETH_HASH_FUNCTION_DEFAULT ? 0 : 2;
    return result;
}
int ntcp_host_test_reta(uint16_t port, uint16_t *reta, uint16_t size) {
    struct rte_eth_rss_reta_entry64 table[size / RTE_ETH_RETA_GROUP_SIZE + 1];
    memset(table, 0, sizeof(table));
    for (uint16_t i = 0; i < size; ++i)
        table[i / RTE_ETH_RETA_GROUP_SIZE].mask |= UINT64_C(1) << (i % RTE_ETH_RETA_GROUP_SIZE);
    int result = rte_eth_dev_rss_reta_query(port, table, size);
    for (uint16_t i = 0; result == 0 && i < size; ++i)
        reta[i] = table[i / RTE_ETH_RETA_GROUP_SIZE].reta[i % RTE_ETH_RETA_GROUP_SIZE];
    return result;
}

// Keeps the ring PMD, and with it the net_ring vdev driver, linked even
// under --as-needed when no other object references it.
void *ntcp_host_test_ring_driver(void) { return (void *)rte_eth_from_rings; }
