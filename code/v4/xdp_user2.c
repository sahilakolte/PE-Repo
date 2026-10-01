// xdp_user2.c
// -----------------------------------------------------------------------
// Program #2 -- consumer. No AF_XDP socket, no NIC, no root needed.
//
// Instead of reading its own RX ring (which, with veth, was filled with
// a COPY of the packet), it:
//   1. reads descriptors {umem offset, len} from the named pipe
//      FIFO_P1_TO_P2 (blocking read -- no busy polling),
//   2. reads the packet in place at  my_umem_base + offset  in the
//      shared UMEM -- the same physical bytes P1 received into,
//   3. writes the offset back to FIFO_P2_TO_P1 so P1 can refill its
//      fill queue with that frame.
//
// Independent process (not a child of xdp_user1); start it in its own
// terminal, before or after xdp_user1.
// -----------------------------------------------------------------------

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "xdp_common.h"

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

int main(void)
{
    // No SA_RESTART: Ctrl+C interrupts the blocking open()/read().
    struct sigaction sa = { .sa_handler = handle_sigint };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    // Map the same physical memory P1 uses as its UMEM. Our virtual
    // address will differ from P1's; that's fine, we only use offsets.
    void *umem_area = shared_umem_create();
    if (!umem_area) return 1;

    // Same order as xdp_user1: P1_TO_P2 first, then P2_TO_P1.
    printf("Waiting for xdp_user1 to open the pipes...\n");
    int fwd_fd = fifo_open(FIFO_P1_TO_P2, O_RDONLY);
    if (fwd_fd < 0) { munmap(umem_area, UMEM_BYTES); return 1; }
    int ret_fd = fifo_open(FIFO_P2_TO_P1, O_WRONLY);
    if (ret_fd < 0) { close(fwd_fd); munmap(umem_area, UMEM_BYTES); return 1; }
    fifo_grow(ret_fd);

    printf("Connected. UMEM mapped at %p in this process. Ctrl+C to stop.\n", umem_area);

    fifo_desc_t in[BATCH_SIZE];
    fifo_desc_t back[BATCH_SIZE];

    while (keep_running) {
        ssize_t n = fifo_read_descs(fwd_fd, in, BATCH_SIZE);   // blocks
        if (n == 0) { printf("xdp_user1 closed the pipe.\n"); break; }
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read " FIFO_P1_TO_P2);
            break;
        }

        size_t m = 0;
        for (ssize_t i = 0; i < n; i++) {
            if (in[i].addr + in[i].len > UMEM_BYTES) {   // never trust the pipe blindly
                fprintf(stderr, "bad descriptor off=0x%llx len=%u\n",
                        (unsigned long long)in[i].addr, in[i].len);
                continue;
            }
            // Offset -> pointer in OUR address space. Zero copy.
            uint8_t *pkt = (uint8_t *)umem_area + in[i].addr;
            print_packet_info(pkt, in[i].addr, in[i].len, "P2");

            back[m++] = (fifo_desc_t){ .addr = in[i].addr };
        }

        // Hand frames back to P1 (stands in for the TX completion ring).
        if (m && fifo_write_descs(ret_fd, back, m) < 0) {
            perror("write " FIFO_P2_TO_P1);
            break;
        }
    }

    printf("\nExiting...\n");
    close(fwd_fd);
    close(ret_fd);
    // Only unmap: P1 owns the UMEM and unlinks the shm name itself.
    munmap(umem_area, UMEM_BYTES);
    return 0;
}
