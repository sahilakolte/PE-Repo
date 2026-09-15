// xdp_kern.c
// -----------------------------------------------------------------------
// This is the small eBPF program that runs INSIDE THE KERNEL, attached to
// a network interface's XDP hook (the earliest point a packet can be
// touched, right after the NIC driver receives it, before the normal
// Linux networking stack even sees it).
//
// Its only job: for every packet that arrives on the interface, look up
// the matching AF_XDP socket in "xsks_map" and hand the packet straight
// to userspace via bpf_redirect_map(). If there is no socket registered
// for this queue, just let the packet pass normally (XDP_PASS).
// -----------------------------------------------------------------------

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// xsks_map is a special "XSKMAP": each entry maps a NIC RX queue index
// to an AF_XDP socket (xsk) that userspace has bound to that queue.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    // If a userspace AF_XDP socket is bound to this RX queue,
    // redirect the raw packet frame straight into it (zero-copy path).
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    // Otherwise, no AF_XDP consumer for this queue -> normal stack.
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
