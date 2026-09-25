// xdp_user2.c
// -----------------------------------------------------------------------
// Userspace program #2 -- a plain consumer, no AF_XDP socket at all.
//
// Under the old veth-based design, this process was itself a genuine
// AF_XDP consumer with its own NIC binding (the veth peer). Now that
// redirection happens via the shared descriptor ring in xdp_common.h
// (see the design note at the top of xdp_user1.c), xdp_user2 has
// nothing left to do with the kernel's AF_XDP subsystem: it never binds
// to an interface, never loads xdp_kern.o, and doesn't need root.
//
// It attaches to the same two shared-memory regions xdp_user1 created:
//   - the shared UMEM, to read packet bytes directly (no copy)
//   - the redirect rings, to receive descriptors and return frames
//
// Per packet:
//   1. Pop a descriptor {addr, len} from redirect_shm->p1_to_p2 -- this
//      is the "RX" side of the handoff, filled by xdp_user1's
//      ksoftirqd_thread.
//   2. Read the packet directly out of the shared UMEM at that address
//      and print it, tagged [P2]. Its hash will match [P1]'s hash
//      exactly, because it's the same physical bytes, not a copy.
//   3. Push the address onto redirect_shm->p2_to_p1 so xdp_user1 can
//      recycle the frame back into its fill queue.
//
// Usage:
//   ./xdp_user2
// -----------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "xdp_common.h"

// typedef struct redirect_shm redirect_shm_t;

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGINT, handle_sigint);

    // Attach to the same physical shared memory xdp_user1 uses. Safe
    // regardless of which process starts first.
    void *umem_area = shared_umem_create();
    if (!umem_area) return 1;

    redirect_shm_t *redirect_shm = redirect_shm_create();
    if (!redirect_shm) { shared_umem_destroy(umem_area); return 1; }

    printf("Waiting for redirected packets from xdp_user1 (no NIC, no root needed). Ctrl+C to stop.\n");

    while (keep_running) {
        uint64_t addr;
        uint32_t len;

        if (!spsc_pop(&redirect_shm->p1_to_p2, &addr, &len)) {
            usleep(1000);
            continue;
        }

        uint8_t *pkt = (uint8_t *)umem_area + addr;
        print_packet_info(pkt, len, "P2");

        // Hand the frame back to xdp_user1 so it can refill its fill
        // queue -- this is the recycling step a real TX completion
        // ring would normally provide.
        while (!spsc_push(&redirect_shm->p2_to_p1, addr, 0)) {
            // Return ring momentarily full (xdp_user1 hasn't drained it
            // yet); briefly back off rather than spin.
            usleep(100);
        }
    }

    printf("\nExiting...\n");
    shared_umem_destroy(umem_area);
    redirect_shm_destroy(redirect_shm);
    return 0;
}
