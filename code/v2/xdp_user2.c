// xdp_user2.c
// -----------------------------------------------------------------------
// Userspace program #2 of the AF_XDP demo.
//
// A completely independent process with its own UMEM and its own real
// AF_XDP socket, bound to "ifname" (the veth peer of xdp_user1's
// tx_ifname, e.g. veth2 when program1 used veth1). Just like the
// original single-process demo, xdp_kern.o is attached to this
// interface's XDP hook so every incoming frame is redirected into this
// socket's RX ring.
//
// Every packet that xdp_user1 transmits on its tx_ifname arrives here
// over the veth wire, gets picked up by the real fill/RX rings below,
// and gets printed tagged [P2] -- so you can watch the same packet's
// 5-tuple show up first as [P1] in program1's log and moments later as
// [P2] here.
//
// Usage:
//   sudo ./xdp_user2 <ifname>
//   e.g. sudo ./xdp_user2 veth2
// -----------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/mman.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "xdp_common.h"

#define RX_BATCH_SIZE   64

static volatile int keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "unknown interface %s\n", ifname); return 1; }

    signal(SIGINT, handle_sigint);

    struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "failed to open xdp_kern.o\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "failed to load BPF object\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");
    int prog_fd = bpf_program__fd(prog);

    int ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (ret) {
        ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (ret) {
            fprintf(stderr, "failed to attach XDP program to %s: %s\n", ifname, strerror(-ret));
            return 1;
        }
        printf("Attached to %s in SKB (generic) mode.\n", ifname);
    } else {
        printf("Attached to %s in native driver mode.\n", ifname);
    }

    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    void *umem_area = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem_area == MAP_FAILED) { perror("mmap umem"); return 1; }

    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };
    ret = xsk_umem__create(&umem, umem_area, NUM_FRAMES * FRAME_SIZE, &fq, &cq, &umem_cfg);
    if (ret) { fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret)); return 1; }

    struct xsk_ring_cons rx;
    struct xsk_socket *xsk;
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY,
    };
    ret = xsk_socket__create(&xsk, ifname, 0, umem, &rx, NULL, &xsk_cfg);
    if (ret) { fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret)); return 1; }

    int sock_fd = xsk_socket__fd(xsk);
    int queue_id = 0;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id, &sock_fd, 0)) {
        fprintf(stderr, "failed to update xsks_map\n");
        return 1;
    }

    uint32_t idx;
    ret = xsk_ring_prod__reserve(&fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) { fprintf(stderr, "failed to reserve fill queue\n"); return 1; }
    for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    printf("Listening on %s (real AF_XDP). Ctrl+C to stop.\n", ifname);

    while (keep_running) {
        uint32_t idx_rx = 0;
        int rcvd = xsk_ring_cons__peek(&rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd) {
            usleep(1000);
            continue;
        }

        uint64_t addrs[RX_BATCH_SIZE];
        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx, idx_rx++);
            addrs[i] = desc->addr;
            uint8_t *pkt = xsk_umem__get_data(umem_area, desc->addr);
            print_packet_info(pkt, desc->len, "P2");
        }
        xsk_ring_cons__release(&rx, rcvd);

        uint32_t idx_fq;
        if (xsk_ring_prod__reserve(&fq, rcvd, &idx_fq) == (uint32_t)rcvd) {
            for (int i = 0; i < rcvd; i++)
                *xsk_ring_prod__fill_addr(&fq, idx_fq + i) = addrs[i];
            xsk_ring_prod__submit(&fq, rcvd);
        }
    }

    printf("\nDetaching XDP program and exiting...\n");
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
    return 0;
}
