#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} steer_port SEC(".maps");

static __always_inline int wanted(struct xdp_md *ctx, __u32 port)
{
    if (port == 0)
        return 1;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_TCP)
        return 0;
    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return 0;

    struct tcphdr *th = (void *)iph + ihl;
    if ((void *)(th + 1) > data_end)
        return 0;

    return bpf_ntohs(th->source) == port;
}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u32 key = 0;
    __u32 *port = bpf_map_lookup_elem(&steer_port, &key);

    if (port && wanted(ctx, *port) && bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
