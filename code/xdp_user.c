// xdp_user.c
// -----------------------------------------------------------------------
// Userspace side of the AF_XDP demo.
//
// What it does:
//   1. Loads xdp_kern.o (the eBPF program above) and attaches it to a
//      network interface given on the command line.
//   2. Creates a UMEM: a chunk of memory shared between kernel and
//      userspace, sliced into fixed-size "frames" that will hold packets.
//   3. Creates an AF_XDP socket (xsk) bound to that interface/queue and
//      registers it in xsks_map so the kernel program redirects packets
//      to it.
//   4. Loops: polls the socket's RX ring, and for every frame that
//      arrives, parses the Ethernet + IPv4 header and prints the
//      source and destination IP address (and protocol).
//
// Usage:
//   sudo ./xdp_user <ifname>
//   e.g. sudo ./xdp_user eth0
// -----------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES      4096
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE   // 4096 bytes
#define RX_BATCH_SIZE   64

static volatile int keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

// Everything needed to run one AF_XDP socket, bundled together.
struct xsk_socket_info {
    struct xsk_ring_cons rx;       // ring the kernel fills with received frames
    struct xsk_ring_prod fq;       // "fill queue": frames we offer for future RX
    struct xsk_umem *umem;         // the shared memory region
    struct xsk_socket *xsk;        // the AF_XDP socket itself
    void *buffer;                  // pointer to the raw UMEM memory
};

static struct xsk_socket_info *xsk_configure(void *umem_area, struct xsk_umem **umem_ptr, const char *ifname, int queue_id)
{
    struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };

    // pointer to completion ring
    struct xsk_ring_cons *comp;
    comp = calloc(1, sizeof(*comp));

    // 1. Register the UMEM (shared packet-buffer memory) with the kernel.
    int ret = xsk_umem__create(umem_ptr, umem_area, NUM_FRAMES * FRAME_SIZE, &xsk_info->fq, comp, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret));
        exit(1);
    }
    
    xsk_info->umem = *umem_ptr;
    xsk_info->buffer = umem_area;

    // 2. Create the AF_XDP socket itself, bound to ifname/queue_id.
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, // we load our own prog
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY, // safest mode; use XDP_ZEROCOPY on supported NICs
    };

    ret = xsk_socket__create(&xsk_info->xsk, ifname, queue_id,
                              xsk_info->umem, &xsk_info->rx, NULL, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret));
        exit(1);
    }

    // 3. Seed the fill queue: hand the kernel a batch of empty frames it
    //    is allowed to fill with incoming packets.
    uint32_t idx;
    ret = xsk_ring_prod__reserve(&xsk_info->fq,
                                  XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        fprintf(stderr, "failed to reserve fill queue entries\n");
        exit(1);
    }
    for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&xsk_info->fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&xsk_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;
}

// Parse and print one Ethernet frame's IPv4 addresses.
static void print_packet_info(uint8_t *pkt, uint32_t len)
{
    if (len < sizeof(struct ethhdr))
        return;

    struct ethhdr *eth = (struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return;

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
        return;

    struct iphdr *iph = (struct iphdr *)(pkt + sizeof(struct ethhdr));

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];

    struct in_addr src = { .s_addr = iph->saddr };
    struct in_addr dst = { .s_addr = iph->daddr };

    strncpy(src_str, inet_ntoa(src), sizeof(src_str));
    src_str[sizeof(src_str) - 1] = '\0';

    strncpy(dst_str, inet_ntoa(dst), sizeof(dst_str));
    dst_str[sizeof(dst_str) - 1] = '\0';

    printf("[XDP] IPv4 packet  len=%u  proto=%u  %s -> %s\n",
           len, iph->protocol, src_str, dst_str);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "unknown interface %s\n", ifname);
        return 1;
    }

    signal(SIGINT, handle_sigint);

    // ---- Load and attach the XDP kernel program ----
    struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "failed to open xdp_kern.o\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");
    int prog_fd = bpf_program__fd(prog);

    int ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (ret) {
        // Fall back to generic/SKB mode if driver mode isn't supported
        // (e.g. veth interfaces, or NIC driver lacks native XDP support).
        ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (ret) {
            fprintf(stderr, "failed to attach XDP program: %s\n", strerror(-ret));
            return 1;
        }
        printf("Attached in SKB (generic) mode.\n");
    } else {
        printf("Attached in native driver mode.\n");
    }

    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    // ---- Set up the AF_XDP socket ----
    void *umem_area = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct xsk_umem *umem;
    struct xsk_socket_info *xsk = xsk_configure(umem_area, &umem, ifname, 0);

    // Tell the kernel program: "packets on queue 0 go to this socket."
    int sock_fd = xsk_socket__fd(xsk->xsk);
    int queue_id = 0;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id, &sock_fd, 0)) {
        fprintf(stderr, "failed to update xsks_map\n");
        return 1;
    }

    printf("Listening for packets on %s (queue 0)... Ctrl+C to stop.\n", ifname);

    // ---- Main receive loop ----
    while (keep_running) {
        uint32_t idx_rx = 0;
        int rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd) {
            usleep(1000);
            continue;
        }

        // Temporary storage for frame addresses to recycle
        uint64_t addrs[RX_BATCH_SIZE];

        for (int i = 0; i < rcvd; i++) {
            // Get the descriptor
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
            
            // Save the address so we can recycle it after processing
            addrs[i] = desc->addr;

            // Get actual data pointer and process
            uint8_t *pkt = xsk_umem__get_data(xsk->buffer, desc->addr);
            print_packet_info(pkt, desc->len);
        }
        xsk_ring_cons__release(&xsk->rx, rcvd);

        // Re-supply the EXACT same addresses back to the fill queue
        uint32_t idx_fq;
        if (xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq) == rcvd) {
            for (int i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&xsk->fq, idx_fq + i) = addrs[i];
            }
            xsk_ring_prod__submit(&xsk->fq, rcvd);
        }
    }

    printf("\nDetaching XDP program and exiting...\n");
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    xsk_socket__delete(xsk->xsk);
    xsk_umem__delete(umem);
    return 0;
}
