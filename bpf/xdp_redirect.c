// [phase 17] The XDP program npf's AF_XDP backend attaches to each port: every frame goes to the
// AF_XDP socket bound to the queue it arrived on. With no socket there, XDP_PASS hands the frame
// on to the kernel, as if the program were not there. Built by src/CMakeLists.txt with clang
// -target bpf, and embedded in the npf binary (ARCHITECTURE.md §9).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int npf_xdp_redirect(struct xdp_md *ctx) {
  return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
