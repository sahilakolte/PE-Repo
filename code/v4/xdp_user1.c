// xdp_user1.c
// -----------------------------------------------------------------------
// Program #1 -- the real AF_XDP receiver.
//
// Receives packets from the NIC into the shared UMEM, then instead of
// putting the descriptor on a TX ring (-> veth -> program #2, which
// costs a copy), it writes the descriptor {umem offset, len} into the
// named pipe FIFO_P1_TO_P2. Program #2 reads the packet in place from
// the same shared UMEM and hands the offset back through FIFO_P2_TO_P1,
// which we recycle into the fill queue.
//
// Usage: sudo ./xdp_user1 <ifname>      (start ./xdp_user2 too, any order)
// -----------------------------------------------------------------------

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <net/if.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "xdp_common.h"

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

// Context for the forwarder thread: a userspace pthread that moves
// packet descriptors from the AF_XDP RX ring into the pipe to xdp_user2,
// and moves returned frames from the return pipe onto the fill queue.
struct forwarder_ctx {
    struct xsk_ring_cons *rxs_rx;
    struct xsk_ring_prod *rx_fq;
    int                   xsk_fd;
    void                 *umem_area;
    int                   fwd_fd;   // FIFO_P1_TO_P2, write end
    int                   ret_fd;   // FIFO_P2_TO_P1, read end (O_NONBLOCK)
};

// Returns 1 if frames were recycled, 0 if none, -1 if P2 went away.
static int recycle_returned_frames(struct forwarder_ctx *ctx)
{
    fifo_desc_t ret[BATCH_SIZE];
    ssize_t n = fifo_read_descs(ctx->ret_fd, ret, BATCH_SIZE);
    if (n == 0) {
        fprintf(stderr, "xdp_user2 closed the return pipe\n");
        return -1;
    }
    if (n < 0)
        return (errno == EAGAIN || errno == EINTR) ? 0 : -1;

    // The fill ring has NUM_FRAMES slots and there are only NUM_FRAMES
    // frames in total, so there is always room; the loop is just defensive.
    uint32_t idx_fq;
    while (xsk_ring_prod__reserve(ctx->rx_fq, (uint32_t)n, &idx_fq) != (uint32_t)n) {
        if (!keep_running) return -1;
        usleep(10);
    }
    for (ssize_t i = 0; i < n; i++)
        *xsk_ring_prod__fill_addr(ctx->rx_fq, idx_fq + (uint32_t)i) = ret[i].addr;
    xsk_ring_prod__submit(ctx->rx_fq, (uint32_t)n);
    return 1;
}

static void *forwarder_thread_fn(void *arg)
{
    struct forwarder_ctx *ctx = (struct forwarder_ctx *)arg;

    // Sleep in poll() instead of usleep(): wake as soon as the NIC
    // delivers packets OR P2 returns frames.
    struct pollfd pfd[2] = {
        { .fd = ctx->xsk_fd, .events = POLLIN },
        { .fd = ctx->ret_fd, .events = POLLIN },
    };

    while (keep_running) {
        // 1. Frames P2 is finished with -> back onto the fill queue.
        int rc = recycle_returned_frames(ctx);
        if (rc < 0) break;

        // 2. Newly received packets -> descriptors into the pipe.
        uint32_t idx_rx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(ctx->rxs_rx, BATCH_SIZE, &idx_rx);
        if (rcvd == 0) {
            if (!rc)
                poll(pfd, 2, 100);   // 100ms cap so Ctrl+C is noticed
            continue;
        }

        fifo_desc_t out[BATCH_SIZE];
        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc *d = xsk_ring_cons__rx_desc(ctx->rxs_rx, idx_rx + i);
            uint8_t *pkt = xsk_umem__get_data(ctx->umem_area, d->addr);
            print_packet_info(pkt, d->addr, d->len, "P1");
            // Only the OFFSET goes into the pipe -- P2 maps the UMEM at a
            // different virtual address, so a pointer would be useless.
            out[i] = (fifo_desc_t){ .addr = d->addr, .len = d->len };
        }
        // Release the RX ring slots. The frames themselves stay owned by
        // us (and then P2) until they come back via the return pipe.
        xsk_ring_cons__release(ctx->rxs_rx, rcvd);

        // One atomic write for the whole batch (<= PIPE_BUF). This is
        // what used to be "put on the TX ring".
        if (fifo_write_descs(ctx->fwd_fd, out, rcvd) < 0) {
            perror("write to " FIFO_P1_TO_P2);
            break;
        }
    }

    keep_running = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <rx_ifname>\n", argv[0]);
        return 1;
    }
    const char *rx_ifname = argv[1];
    int rx_ifindex = if_nametoindex(rx_ifname);
    if (!rx_ifindex) { fprintf(stderr, "unknown interface %s\n", rx_ifname); return 1; }

    // No SA_RESTART: lets Ctrl+C interrupt the blocking FIFO open().
    struct sigaction sa = { .sa_handler = handle_sigint };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    // If P2 dies, write() returns EPIPE instead of killing us.
    signal(SIGPIPE, SIG_IGN);

    // ---- Rendezvous with xdp_user2 over the named pipes ----
    // Done before attaching XDP, so the NIC isn't hijacked while we wait.
    // Order must match xdp_user2: P1_TO_P2 first, then P2_TO_P1.
    printf("Waiting for xdp_user2 to open the pipes...\n");
    int fwd_fd = fifo_open(FIFO_P1_TO_P2, O_WRONLY);
    if (fwd_fd < 0) return 1;
    int ret_fd = fifo_open(FIFO_P2_TO_P1, O_RDONLY);
    if (ret_fd < 0) { close(fwd_fd); return 1; }
    fifo_grow(fwd_fd);
    fcntl(ret_fd, F_SETFL, fcntl(ret_fd, F_GETFL) | O_NONBLOCK);
    printf("xdp_user2 connected.\n");

    // ---- Load and attach the XDP program ----
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

    // ---- UMEM on top of the shared memory region ----
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
    ret = xsk_umem__create(&umem, umem_area, UMEM_BYTES, &rx_fq, &rx_cq, &umem_cfg);
    if (ret) { fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret)); return 1; }

    // ---- Give every frame to the kernel via the fill queue ----
    uint32_t idx;
    uint32_t nfill = xsk_prod_nb_free(&rx_fq, NUM_FRAMES);
    if (xsk_ring_prod__reserve(&rx_fq, nfill, &idx) != nfill) {
        fprintf(stderr, "failed to reserve fill queue\n");
        return 1;
    }
    for (uint32_t i = 0; i < nfill; i++)
        *xsk_ring_prod__fill_addr(&rx_fq, idx + i) = (uint64_t)i * FRAME_SIZE;
    xsk_ring_prod__submit(&rx_fq, nfill);

    // ---- AF_XDP socket (RX only; no TX ring needed any more) ----
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
        fprintf(stderr, "xsk_socket__create failed: %d (%s)\n", ret, strerror(-ret));
        return 1;
    }

    int xsk_fd = xsk_socket__fd(rxs);
    int queue_id = 0;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id, &xsk_fd, 0)) {
        fprintf(stderr, "failed to update xsks_map\n");
        return 1;
    }

    printf("RX on %s. Forwarding descriptors to xdp_user2 via %s. Ctrl+C to stop.\n",
           rx_ifname, FIFO_P1_TO_P2);

    struct forwarder_ctx ctx = {
        .rxs_rx = &rxs_rx,
        .rx_fq = &rx_fq,
        .xsk_fd = xsk_fd,
        .umem_area = umem_area,
        .fwd_fd = fwd_fd,
        .ret_fd = ret_fd,
    };
    pthread_t tid;
    if (pthread_create(&tid, NULL, forwarder_thread_fn, &ctx)) {
        perror("pthread_create");
        return 1;
    }

    // The forwarder exits on Ctrl+C (it re-checks keep_running at least
    // every 100ms) or when xdp_user2 goes away.
    pthread_join(tid, NULL);

    printf("\nDetaching XDP program and exiting...\n");
    bpf_xdp_detach(rx_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    close(fwd_fd);        // xdp_user2 sees EOF and exits
    close(ret_fd);

    struct xdp_statistics st; socklen_t sl = sizeof(st);
    if (!getsockopt(xsk_fd, SOL_XDP, XDP_STATISTICS, &st, &sl))
        printf("rx_dropped=%llu fill_ring_empty=%llu\n",
            (unsigned long long)st.rx_dropped,
            (unsigned long long)st.rx_fill_ring_empty_descs);

    xsk_socket__delete(rxs);
    xsk_umem__delete(umem);
    shared_umem_destroy(umem_area);
    bpf_object__close(obj);
    return 0;
}
