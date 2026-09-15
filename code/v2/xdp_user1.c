// xdp_user1.c
// -----------------------------------------------------------------------
// Userspace program #1 of the AF_XDP demo.
//
// This process owns TWO AF_XDP sockets that share a single UMEM:
//
//   rxs  - bound to the real NIC ("rx_ifname"), queue 0. This is the
//          genuine AF_XDP consumer: xdp_kern.o is attached to the NIC's
//          XDP hook and redirects incoming frames into rxs's RX ring,
//          exactly like the original single-process demo.
//
//   txs  - bound to a veth interface ("tx_ifname", e.g. veth1), queue 0.
//          TX-only: no XDP program needed for a socket that only sends.
//
// Because rxs and txs share the SAME umem (via xsk_socket__create_shared),
// a frame that lands in rxs's RX ring can be hand off to txs's TX ring
// by copying only the descriptor (addr, len) -- the packet bytes
// themselves never move. That's the "zero copy" part: we literally
// re-use rxs's frame address as txs's TX descriptor address.
//
// Per packet:
//   1. Frame arrives in rxs.rx (real AF_XDP receive, via xdp_kern.o).
//   2. We print it, tagged [P1].
//   3. We submit that same frame address onto txs.tx and kick the
//      socket with sendto() -- this ACTUALLY transmits the frame out
//      tx_ifname. On the other end of the veth pair, xdp_user2 receives
//      it on its own real AF_XDP RX ring.
//   4. Once the kernel reports the send complete (txs's completion
//      ring), we know the frame is free again and recycle its address
//      into rxs's fill queue so the NIC can reuse it.
//
// No custom shared-memory ring is used anywhere -- steps 3/4 are the
// real AF_XDP TX ring + completion ring, and the "handoff" to program2
// is a real packet transmission over a veth wire.
//
// Usage:
//   sudo ./xdp_user1 <rx_ifname> <tx_ifname>
//   e.g. sudo ./xdp_user1 eth0 veth1
// -----------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>

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
    if (argc != 3) {
        fprintf(stderr, "usage: %s <rx_ifname> <tx_ifname>\n", argv[0]);
        fprintf(stderr, "  rx_ifname: real NIC to sniff (e.g. eth0)\n");
        fprintf(stderr, "  tx_ifname: veth end that hands frames to program2 (e.g. veth1)\n");
        return 1;
    }
    const char *rx_ifname = argv[1];
    const char *tx_ifname = argv[2];

    int rx_ifindex = if_nametoindex(rx_ifname);
    if (!rx_ifindex) { fprintf(stderr, "unknown interface %s\n", rx_ifname); return 1; }
    int tx_ifindex = if_nametoindex(tx_ifname);
    if (!tx_ifindex) { fprintf(stderr, "unknown interface %s\n", tx_ifname); return 1; }

    signal(SIGINT, handle_sigint);

    // ---- Load and attach the XDP kernel program to the *real* NIC only.
    // The veth TX socket never receives in this process, so it needs no
    // XDP program at all.
    struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "failed to open xdp_kern.o\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "failed to load BPF object\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");
    int prog_fd = bpf_program__fd(prog);

    int ret = bpf_xdp_attach(rx_ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (ret) {
        ret = bpf_xdp_attach(rx_ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (ret) {
            fprintf(stderr, "failed to attach XDP program to %s: %s\n", rx_ifname, strerror(-ret));
            return 1;
        }
        printf("Attached to %s in SKB (generic) mode.\n", rx_ifname);
    } else {
        printf("Attached to %s in native driver mode.\n", rx_ifname);
    }

    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    // ---- One UMEM, shared by both sockets. ----
    void *umem_area = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem_area == MAP_FAILED) { perror("mmap umem"); return 1; }

    struct xsk_umem *umem;
    struct xsk_ring_prod rx_fq;   // fill queue for the RX (real NIC) socket
    struct xsk_ring_cons rx_cq;   // completion ring returned by xsk_umem__create; unused directly (rxs never transmits)
    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };
    ret = xsk_umem__create(&umem, umem_area, NUM_FRAMES * FRAME_SIZE, &rx_fq, &rx_cq, &umem_cfg);
    if (ret) { fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret)); return 1; }

    // ---- Socket 1: RX-only, bound to the real NIC. ----
    struct xsk_ring_cons rxs_rx;
    struct xsk_socket *rxs;
    struct xsk_socket_config rx_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, // we loaded our own prog above
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY,
    };
    ret = xsk_socket__create(&rxs, rx_ifname, 0, umem, &rxs_rx, NULL, &rx_cfg);
    if (ret) { fprintf(stderr, "xsk_socket__create (rx) failed: %s\n", strerror(-ret)); return 1; }

    int rx_sock_fd = xsk_socket__fd(rxs);
    int queue_id = 0;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id, &rx_sock_fd, 0)) {
        fprintf(stderr, "failed to update xsks_map\n");
        return 1;
    }

    // Seed the RX socket's fill queue with every frame up front. Frames
    // that get handed off to program2 simply won't come back here until
    // the TX completion ring reports them (see the main loop).
    uint32_t idx;
    ret = xsk_ring_prod__reserve(&rx_fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) { fprintf(stderr, "failed to reserve fill queue\n"); return 1; }
    for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&rx_fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&rx_fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    // ---- Socket 2: TX-only, bound to the veth interface, SHARING umem
    // with socket 1. Binding shared umem to a *different* netdev needs
    // its own fresh fill/completion ring pair (kernel requirement) --
    // xsk_socket__create_shared allocates/populates those for us. We
    // only ever use tx_cq (completion); tx_fq stays empty since this
    // socket never receives.
    struct xsk_ring_prod tx_fq;
    struct xsk_ring_cons tx_cq;
    struct xsk_ring_prod txs_tx;
    struct xsk_socket *txs;
    struct xsk_socket_config tx_cfg = {
        .rx_size = 0,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = 0,   // no XDP program needed on a TX-only socket
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_COPY,
    };
    ret = xsk_socket__create_shared(&txs, tx_ifname, 0, umem, NULL /* rx */, &txs_tx, &tx_fq, &tx_cq, &tx_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create_shared (tx on %s) failed: %s\n", tx_ifname, strerror(-ret));
        fprintf(stderr, "  (make sure %s exists, e.g. `make veth-setup`)\n", tx_ifname);
        return 1;
    }

    printf("RX on %s (real AF_XDP), TX handoff to %s (real AF_XDP, shared umem).\n", rx_ifname, tx_ifname);
    printf("Ctrl+C to stop.\n");

    while (keep_running) {
        // 1) Reap completed transmissions and give those frames back to
        //    the RX socket's fill queue -- the real completion-ring ->
        //    fill-ring recycle step, just spanning two sockets that
        //    happen to share a umem.
        uint32_t idx_cq;
        int ncomp = xsk_ring_cons__peek(&tx_cq, RX_BATCH_SIZE, &idx_cq);
        if (ncomp > 0) {
            uint32_t idx_fq;
            if (xsk_ring_prod__reserve(&rx_fq, ncomp, &idx_fq) == (uint32_t)ncomp) {
                for (int i = 0; i < ncomp; i++) {
                    uint64_t addr = *xsk_ring_cons__comp_addr(&tx_cq, idx_cq + i);
                    *xsk_ring_prod__fill_addr(&rx_fq, idx_fq + i) = addr;
                }
                xsk_ring_prod__submit(&rx_fq, ncomp);
            }
            xsk_ring_cons__release(&tx_cq, ncomp);
        }

        // 2) Read newly arrived frames from the real RX ring.
        uint32_t idx_rx = 0;
        int rcvd = xsk_ring_cons__peek(&rxs_rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd) {
            usleep(1000);
            continue;
        }

        uint32_t idx_tx;
        int reserved = xsk_ring_prod__reserve(&txs_tx, rcvd, &idx_tx);
        int handed_off = 0;

        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rxs_rx, idx_rx++);
            uint8_t *pkt = xsk_umem__get_data(umem_area, desc->addr);
            print_packet_info(pkt, desc->len, "P1");

            if (i < reserved) {
                // Hand this exact frame (same address, no copy) to the
                // TX ring -- it will physically go out tx_ifname.
                struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&txs_tx, idx_tx + i);
                tx_desc->addr = desc->addr;
                tx_desc->len = desc->len;
                handed_off++;
            }
            // (If the TX ring was full we simply drop the frame here in
            // this demo rather than queueing it
        }
        xsk_ring_cons__release(&rxs_rx, rcvd);

        if (handed_off > 0) {
            xsk_ring_prod__submit(&txs_tx, handed_off);
            // Kick the kernel to actually send what's on the TX ring.
            if (sendto(xsk_socket__fd(txs), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0 && errno != EAGAIN)
                perror("sendto (tx kick)");
        }
    }

    printf("\nDetaching XDP program and exiting...\n");
    bpf_xdp_detach(rx_ifindex, XDP_FLAGS_DRV_MODE, NULL);
    xsk_socket__delete(txs);
    xsk_socket__delete(rxs);
    xsk_umem__delete(umem);
    munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
    return 0;
}
