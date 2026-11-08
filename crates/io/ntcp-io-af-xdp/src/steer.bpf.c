// XDP program of the AF_XDP host (host.rs). Frames addressed to an ntcp IPv4
// address go to the AF_XDP socket of the queue they arrived on: IPv4 by
// destination, Ethernet/IPv4 ARP by target protocol address. Everything else
// passes to the kernel unchanged, so the interface keeps its kernel traffic.
// An ntcp frame on a queue without a socket is dropped, never passed: the
// kernel does not own these addresses, and the drop is counted, as it shows
// that steering does not match the sockets' queues.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// The loader sets max_entries of the address and socket maps.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32); // IPv4 address, network byte order
    __type(value, __u8);
} ntcp_addresses SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32); // RX queue index
    __type(value, __u32);
} ntcp_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ntcp_unsteered SEC(".maps");

SEC("xdp")
int ntcp_steer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u8 *l3 = (__u8 *)(eth + 1);
    __u32 target;

    if ((void *)l3 > end)
        return XDP_PASS;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // Destination address at offset 16; ntcp validates the rest.
        if ((void *)(l3 + 20) > end)
            return XDP_PASS;
        __builtin_memcpy(&target, l3 + 16, 4);
    } else if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        // RFC 826 for Ethernet and IPv4 (htype 1, ptype 0x0800, hlen 6,
        // plen 4): the target protocol address is at offset 24.
        if ((void *)(l3 + 28) > end)
            return XDP_PASS;
        if (l3[0] != 0 || l3[1] != 1 || l3[2] != 0x08 || l3[3] != 0 || l3[4] != 6 || l3[5] != 4)
            return XDP_PASS;
        __builtin_memcpy(&target, l3 + 24, 4);
    } else {
        return XDP_PASS;
    }
    if (!bpf_map_lookup_elem(&ntcp_addresses, &target))
        return XDP_PASS;
    // The default action (low bits of flags) applies when the queue has no socket.
    if (bpf_redirect_map(&ntcp_sockets, ctx->rx_queue_index, XDP_ABORTED) == XDP_REDIRECT)
        return XDP_REDIRECT;
    __u32 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&ntcp_unsteered, &zero);
    if (count)
        *count += 1;
    return XDP_DROP;
}

// The crate's license; the program calls no GPL-only helper.
char LICENSE[] SEC("license") = "MIT";
