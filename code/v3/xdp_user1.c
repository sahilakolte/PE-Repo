// xdp_user1.c
// -----------------------------------------------------------------------
// Userspace program #1 -- the real AF_XDP receiver.
// -----------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <net/if.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "xdp_common.h"

#define RX_BATCH_SIZE   64

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

struct ksoftirqd_ctx {
    struct xsk_ring_cons *rxs_rx;
    struct xsk_ring_prod *rx_fq;
    void                 *umem_area;
    redirect_shm_t        *redirect_shm;
};

static void *ksoftirqd_thread_fn(void *arg)
{
    struct ksoftirqd_ctx *ctx = (struct ksoftirqd_ctx *)arg;

    while (keep_running) {
        int did_work = 0;

        uint32_t nreturn = 0;
        uint64_t returned_addrs[RX_BATCH_SIZE];
        while (nreturn < RX_BATCH_SIZE &&
               spsc_pop(&ctx->redirect_shm->p2_to_p1, &returned_addrs[nreturn], NULL))
            nreturn++;
        if (nreturn > 0) {
            uint32_t idx_fq;
            if (xsk_ring_prod__reserve(ctx->rx_fq, nreturn, &idx_fq) == nreturn) {
                for (uint32_t i = 0; i < nreturn; i++)
                    *xsk_ring_prod__fill_addr(ctx->rx_fq, idx_fq + i) = returned_addrs[i];
                xsk_ring_prod__submit(ctx->rx_fq, nreturn);
            }
            did_work = 1;
        }

        uint32_t idx_rx = 0;
        int rcvd = xsk_ring_cons__peek(ctx->rxs_rx, RX_BATCH_SIZE, &idx_rx);
        if (rcvd <= 0) {
            if (!did_work)
                usleep(1000);
            continue;
        }

        int redirected = 0;
        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(ctx->rxs_rx, idx_rx++);
            uint8_t *pkt = xsk_umem__get_data(ctx->umem_area, desc->addr);
            print_packet_info(pkt, desc->len, "P1");

            if (spsc_push(&ctx->redirect_shm->p1_to_p2, desc->addr, desc->len)) {
                redirected++;
            }
        }
        xsk_ring_cons__release(ctx->rxs_rx, rcvd);
        (void)redirected;
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <rx_ifname>\n", argv[0]);
        fprintf(stderr, "  rx_ifname: real NIC to sniff (e.g. eth0)\n");
        return 1;
    }
    const char *rx_ifname = argv[1];

    int rx_ifindex = if_nametoindex(rx_ifname);
    if (!rx_ifindex) { fprintf(stderr, "unknown interface %s\n", rx_ifname); return 1; }

    signal(SIGINT, handle_sigint);

    // ---- Load and attach the XDP kernel program to the real NIC. ----
    struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "failed to open xdp_kern.o\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "failed to load BPF object\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");
    int prog_fd = bpf_program__fd(prog);

    int ret = bpf_xdp_attach(rx_ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (ret) {
        fprintf(stderr, "failed to attach XDP program to %s: %s\n", rx_ifname, strerror(-ret));
        return 1;
    }
    printf("Attached to %s in SKB (generic) mode.\n", rx_ifname);

    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    // ---- UMEM Creation ----
    void *umem_area = shared_umem_create();
    if (!umem_area) return 1;

    struct xsk_umem *umem;
    struct xsk_ring_prod rx_fq;
    struct xsk_ring_cons rx_cq; 
    struct xsk_umem_config umem_cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };
    ret = xsk_umem__create(&umem, umem_area, NUM_FRAMES * FRAME_SIZE, &rx_fq, &rx_cq, &umem_cfg);
    if (ret) { fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret)); return 1; }

    // ---- Fill Queue Initialization ----
    // Query available free space in the fill ring before reserving
    uint32_t idx;
    uint32_t num_to_reserve = xsk_prod_nb_free(&rx_fq, NUM_FRAMES);

    if (num_to_reserve == 0) {
        fprintf(stderr, "fill queue has 0 free slots\n");
        return 1;
    }

    ret = xsk_ring_prod__reserve(&rx_fq, num_to_reserve, &idx);
    if (ret != num_to_reserve) {
        fprintf(stderr, "failed to reserve fill queue: requested %u, got %u\n", num_to_reserve, ret);
        return 1;
    }
    for (uint32_t i = 0; i < num_to_reserve; i++)
        *xsk_ring_prod__fill_addr(&rx_fq, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&rx_fq, num_to_reserve);

    // ---- AF_XDP Socket Creation ----
    struct xsk_ring_cons rxs_rx;
    struct xsk_socket *rxs;
    struct xsk_socket_config rx_cfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY,
    };
    ret = xsk_socket__create(&rxs, rx_ifname, 0, umem, &rxs_rx, NULL, &rx_cfg);
    if (ret < 0) { 
        fprintf(stderr, "xsk_socket__create (rx) failed: %d (%s)\n", ret, strerror(-ret)); 
        return 1; 
    }

    int rx_sock_fd = xsk_socket__fd(rxs);
    int queue_id = 0;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id, &rx_sock_fd, 0)) {
        fprintf(stderr, "failed to update xsks_map\n");
        return 1;
    }

    // ---- Shared Memory Setup ----
    redirect_shm_t *redirect_shm = redirect_shm_create();
    if (!redirect_shm) return 1;

    printf("RX on %s (real AF_XDP). Redirecting to xdp_user2 via shared memory (no veth).\n", rx_ifname);
    printf("Ctrl+C to stop.\n");

    struct ksoftirqd_ctx ctx = {
        .rxs_rx = &rxs_rx,
        .rx_fq = &rx_fq,
        .umem_area = umem_area,
        .redirect_shm = redirect_shm,
    };
    pthread_t ksoftirqd_tid;
    if (pthread_create(&ksoftirqd_tid, NULL, ksoftirqd_thread_fn, &ctx)) {
        perror("pthread_create (ksoftirqd_thread)");
        return 1;
    }

    while (keep_running)
        sleep(1);

    pthread_join(ksoftirqd_tid, NULL);

    printf("\nDetaching XDP program and exiting...\n");
    bpf_xdp_detach(rx_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    xsk_socket__delete(rxs);
    xsk_umem__delete(umem);
    shared_umem_destroy(umem_area);
    redirect_shm_destroy(redirect_shm);
    return 0;
}