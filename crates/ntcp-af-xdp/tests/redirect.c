#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xsks SEC(".maps");
SEC("xdp") int redirect(struct xdp_md *ctx) {
    return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_PASS);
}
char LICENSE[] SEC("license") = "GPL";
