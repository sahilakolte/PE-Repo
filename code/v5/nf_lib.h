// nf_run() does the following:
//   1. connects to the monitor over MONITOR_SOCK and sends its name,
//   2. receives {umem fd, in fd, out fd} and mmaps the shared UMEM,
//   3. loops: read descriptors from "in" -> call the handler on the
//      packet IN PLACE in the shared UMEM -> write descriptors to "out".

#ifndef NF_LIB_H
#define NF_LIB_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "xdp_common.h"

struct nf_pkt {
    uint8_t  *data;
    uint32_t  len;
    uint64_t  off;
};

typedef void (*nf_handler_t)(struct nf_pkt *pkt);

static volatile sig_atomic_t nf_keep_running = 1;
static void nf_on_signal(int sig) { 
    (void)sig; 
    nf_keep_running = 0; 
}

// Connect to the monitor, retrying until it is up
static int nf_connect_monitor(void)
{
    int announced = 0;
    while (nf_keep_running) {
        int s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (s < 0) { perror("socket"); return -1; }
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        strncpy(sa.sun_path, MONITOR_SOCK, sizeof(sa.sun_path) - 1);
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0)
            return s;
        close(s);
        if (errno != ENOENT && errno != ECONNREFUSED) { perror("connect"); return -1; }
        if (!announced) { printf("Waiting for the monitor at %s...\n", MONITOR_SOCK); announced = 1; }
        sleep(1);
    }
    return -1;
}

static int nf_run(const char *name, nf_handler_t handler)
{
    // No SA_RESTART: Ctrl+C interrupts the blocking read().
    struct sigaction sa = { .sa_handler = nf_on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);   // line-buffered even when piped

    // ---- 1. Register with the monitor ----
    int s = nf_connect_monitor();
    if (s < 0) return 1;

    struct nf_hello hello = {0};
    strncpy(hello.name, name, sizeof(hello.name) - 1);
    if (send(s, &hello, sizeof(hello), MSG_NOSIGNAL) != sizeof(hello)) {
        perror("send hello");
        return 1;
    }

    // ---- 2. Receive the UMEM fd and our two pipe ends ----
    struct nf_welcome w;
    int fds[WELCOME_NFDS], nfds = 0;
    ssize_t r = uds_recv(s, &w, sizeof(w), fds, &nfds);
    close(s);   // the control channel is only needed for setup
    if (r != (ssize_t)sizeof(w)) { fprintf(stderr, "bad reply from monitor\n"); return 1; }
    if (w.status != 0) { fprintf(stderr, "monitor refused %s: %s\n", name, w.msg); return 1; }
    if (nfds != WELCOME_NFDS) { fprintf(stderr, "monitor sent %d fds, expected 3\n", nfds); return 1; }

    int umem_fd = fds[0], in_fd = fds[1], out_fd = fds[2];
    size_t umem_bytes = (size_t)w.umem_bytes;
    uint8_t *umem = mmap(NULL, umem_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, umem_fd, 0);
    close(umem_fd);   // the mapping stays valid
    if (umem == MAP_FAILED) { perror("mmap umem"); return 1; }

    printf("[%s] registered. UMEM mapped at %p. Waiting for packets...\n", name, (void *)umem);

    // ---- 3. Datapath: in -> handler -> out ----
    fifo_desc_t d[BATCH_SIZE];
    unsigned long long seen = 0;

    while (nf_keep_running) {
        ssize_t n = fifo_read_descs(in_fd, d, BATCH_SIZE);   // blocks
        if (n == 0) { printf("[%s] upstream closed.\n", name); break; }
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read in");
            break;
        }

        for (ssize_t i = 0; i < n; i++) {
            if (d[i].addr + d[i].len > umem_bytes) {   // never trust a descriptor
                fprintf(stderr, "[%s] bad descriptor off=0x%llx len=%u, passing it on untouched\n",
                        name, (unsigned long long)d[i].addr, d[i].len);
                continue;
            }
            struct nf_pkt p = { p.data = umem + d[i].addr, p.len = d[i].len, p.off = d[i].addr };
            handler(&p);
            seen++;
        }

        // Pass the whole batch on. The frames must eventually get back to
        // the monitor to be recycled, and we don't know who is next.
        if (fifo_write_descs(out_fd, d, (size_t)n) < 0) {
            if (errno == EPIPE) printf("[%s] downstream closed.\n", name);
            else perror("write out");
            break;
        }
    }

    printf("[%s] exiting. packets=%llu\n", name, seen);
    close(in_fd);
    close(out_fd);    // downstream sees EOF, so shutdown ripples down the chain
    munmap(umem, umem_bytes);
    return 0;
}

#endif // NF_LIB_H
