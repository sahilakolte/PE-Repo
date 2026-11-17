// reads chain.conf (interface, port filter, sink, NF order),
// creates the shared UMEM (a memfd) and one pipe per hop:
//
//        p0          p1          p2               pN
//   MON ----> NF1 ----> NF2 ----> ...  ---> NFN ----> MON
//
//   listens on MONITOR_SOCK. When an NF connects and says its name,
//   the monitor looks up its position in the chain and hands it
//   {umem fd, read end of p[i], write end of p[i+1]} with SCM_RIGHTS.
//
// Sinks:
//   stack: write the frame into a TAP device so the kernel receives it
//          as if it came off the wire, and the HTTP client gets its
//          response..
//   drop:  just recycle the frame.
//
// Usage: sudo ./monitor [chain.conf] [ifname]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include "xdp_common.h"

#define TAP_NAME  "flash0"
#define TAP_ADDR  "169.254.250.1"   // any /32; only there so rp_filter accepts packets

static volatile sig_atomic_t keep_running = 1;
static void on_signal(int sig) { (void)sig; keep_running = 0; }

// ------------------------------------------------------------------ config
struct config {
    char     iface[IF_NAMESIZE];
    uint32_t port;
    int      sink_stack;             // 1 = stack, 0 = drop
    int      n;                      // chain length
    char     nf[MAX_CHAIN][NF_NAME_MAX];
};

static int load_config(const char *path, struct config *c)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    memset(c, 0, sizeof(*c));
    strcpy(c->iface, "wlp0s20f3");
    c->port = 80;
    c->sink_stack = 1;

    char line[512];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *key = strtok(line, " \t\r\n");
        if (!key) continue;

        if (!strcmp(key, "iface")) {
            char *v = strtok(NULL, " \t\r\n");
            if (v) snprintf(c->iface, sizeof(c->iface), "%s", v);
        } else if (!strcmp(key, "port")) {
            char *v = strtok(NULL, " \t\r\n");
            if (v) c->port = (uint32_t)strtoul(v, NULL, 10);
        } else if (!strcmp(key, "sink")) {
            char *v = strtok(NULL, " \t\r\n");
            if (v && !strcmp(v, "drop")) c->sink_stack = 0;
            else if (v && !strcmp(v, "stack")) c->sink_stack = 1;
            else { fprintf(stderr, "%s:%d: sink must be 'stack' or 'drop'\n", path, lineno); fclose(f); return -1; }
        } else if (!strcmp(key, "chain") || !strcmp(key, "nf")) {
            for (char *v; (v = strtok(NULL, " \t\r\n")); ) {
                if (c->n == MAX_CHAIN) { fprintf(stderr, "too many NFs (max %d)\n", MAX_CHAIN); fclose(f); return -1; }
                for (int i = 0; i < c->n; i++)
                    if (!strcmp(c->nf[i], v)) { fprintf(stderr, "%s:%d: '%s' listed twice\n", path, lineno, v); fclose(f); return -1; }
                snprintf(c->nf[c->n++], NF_NAME_MAX, "%s", v);
            }
        } else {
            fprintf(stderr, "%s:%d: unknown key '%s'\n", path, lineno, key);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    if (c->n == 0) { fprintf(stderr, "%s: no NFs in 'chain'\n", path); return -1; }
    return 0;
}

// ------------------------------------------------------------- TAP (sink)
// Creates TAP_NAME, brings it up with a /32 address, and turns off strict
// reverse-path filtering on it. The re-injected packet arrives on the TAP,
// while the route back to its source goes out the real NIC. Strict
// rp_filter would drop it, loose (2) or off (0) accepts it.
static int tap_open(uint8_t mac[ETH_ALEN])
{
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("/dev/net/tun"); return -1; }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, TAP_NAME, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }

    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); goto fail; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, TAP_ADDR, &sin->sin_addr);
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) { perror("SIOCSIFADDR"); goto fail; }
    inet_pton(AF_INET, "255.255.255.255", &sin->sin_addr);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) { perror("SIOCSIFNETMASK"); goto fail; }

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { perror("SIOCGIFFLAGS"); goto fail; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { perror("SIOCSIFFLAGS"); goto fail; }
    close(s);

    FILE *rp = fopen("/proc/sys/net/ipv4/conf/" TAP_NAME "/rp_filter", "w");
    if (rp) { fputs("0", rp); fclose(rp); }
    rp = fopen("/proc/sys/net/ipv4/conf/all/rp_filter", "r");
    if (rp) {
        int all = 0;
        if (fscanf(rp, "%d", &all) == 1 && all == 1)
            fprintf(stderr,
                "WARNING: net.ipv4.conf.all.rp_filter=1 (strict) will drop re-injected packets.\n"
                "         Run: sudo sysctl -w net.v4.conf.all.rp_filter=2\n");
        fclose(rp);
    }
    return fd;
fail:
    close(s);
    close(fd);
    return -1;
}

// Hand one frame to the kernel stack. The destination MAC is rewritten
// to the TAP's MAC, otherwise the kernel treats it as "not for this host".
static void tap_inject(int tap_fd, const uint8_t mac[ETH_ALEN], uint8_t *pkt, uint32_t len)
{
    if (len < sizeof(struct ethhdr)) return;
    memcpy(((struct ethhdr *)pkt)->h_dest, mac, ETH_ALEN);
    if (write(tap_fd, pkt, len) < 0 && errno != EAGAIN)
        perror("write " TAP_NAME);
}

// ------------------------------------------------------------- chain setup
struct hop { int rd, wr; };          // p[i]: read end, write end

static void close_fd(int *fd) { if (*fd >= 0) { close(*fd); *fd = -1; } }

static int listen_monitor_sock(void)
{
    unlink(MONITOR_SOCK);
    int s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (s < 0) { perror("socket"); return -1; }
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    strncpy(sa.sun_path, MONITOR_SOCK, sizeof(sa.sun_path) - 1);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind " MONITOR_SOCK); close(s); return -1; }
    chmod(MONITOR_SOCK, 0666);       // non-root NFs may connect
    if (listen(s, MAX_CHAIN) < 0) { perror("listen"); close(s); return -1; }
    return s;
}

static void reply_error(int c, const char *fmt, const char *name)
{
    struct nf_welcome w = { .status = -1 };
    snprintf(w.msg, sizeof(w.msg), fmt, name);
    uds_send(c, &w, sizeof(w), NULL, 0);
    fprintf(stderr, "rejected: %s\n", w.msg);
}

// Accept NFs until every NF in the chain has registered. NF i gets
// p[i].rd as its input and p[i+1].wr as its output.
static int wait_for_nfs(int lfd, const struct config *cfg, struct hop *p, int umem_fd)
{
    int registered[MAX_CHAIN] = {0};
    int remaining = cfg->n;

    printf("Waiting for %d NF(s):", cfg->n);
    for (int i = 0; i < cfg->n; i++) printf(" %s", cfg->nf[i]);
    printf("\n");

    while (remaining > 0 && keep_running) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        if (poll(&pfd, 1, 500) <= 0) continue;

        int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;

        struct nf_hello h;
        if (recv(c, &h, sizeof(h), 0) != (ssize_t)sizeof(h)) { close(c); continue; }
        h.name[NF_NAME_MAX - 1] = '\0';

        int i = -1;
        for (int k = 0; k < cfg->n; k++)
            if (!strcmp(cfg->nf[k], h.name)) { i = k; break; }

        if (i < 0)                { reply_error(c, "'%s' is not in the chain", h.name); close(c); continue; }
        if (registered[i])        { reply_error(c, "'%s' is already registered", h.name); close(c); continue; }

        struct nf_welcome w = { .status = 0, .umem_bytes = UMEM_BYTES };
        int fds[WELCOME_NFDS] = { umem_fd, p[i].rd, p[i + 1].wr };
        if (uds_send(c, &w, sizeof(w), fds, WELCOME_NFDS) < 0) {
            perror("send fds");
            close(c);
            continue;
        }
        close(c);

        // The NF owns these ends now. Dropping our copies matters: it is
        // what lets EOF/EPIPE ripple along the chain when an NF exits.
        close_fd(&p[i].rd);
        close_fd(&p[i + 1].wr);
        registered[i] = 1;
        remaining--;

        const char *from = (i == 0) ? "monitor" : cfg->nf[i - 1];
        const char *to   = (i == cfg->n - 1) ? "monitor" : cfg->nf[i + 1];
        printf("  + %-8s registered  (%s -> %s -> %s)  %d left\n", h.name, from, h.name, to, remaining);
    }
    return remaining == 0 ? 0 : -1;
}

// -------------------------------------------------------------- datapath
struct dp {
    struct xsk_ring_cons *rx;
    struct xsk_ring_prod *fq;
    void    *umem;
    int      xsk_fd;
    int      to_chain;    // p0 write end
    int      from_chain;  // pN read end (O_NONBLOCK)
    int      tap_fd;      // -1 for sink=drop
    uint8_t  tap_mac[ETH_ALEN];
};

// Frames coming out of the last NF: deliver (or not), then recycle.
// Returns 1 if frames were handled, 0 if none, -1 if the chain broke.
static int drain_chain(struct dp *dp)
{
    fifo_desc_t d[BATCH_SIZE];
    ssize_t n = fifo_read_descs(dp->from_chain, d, BATCH_SIZE);
    if (n == 0) { fprintf(stderr, "chain closed: an NF exited\n"); return -1; }
    if (n < 0) return (errno == EAGAIN || errno == EINTR) ? 0 : -1;

    for (ssize_t i = 0; i < n; i++) {
        if (d[i].addr + d[i].len > UMEM_BYTES) continue;   // corrupt: leak rather than misuse
        uint8_t *pkt = xsk_umem__get_data(dp->umem, d[i].addr);
        if (dp->tap_fd >= 0) {                 // sink stack; sink drop does nothing
            print_packet_info(pkt, d[i].addr, d[i].len, "OUT");
            tap_inject(dp->tap_fd, dp->tap_mac, pkt, d[i].len);
        }
    }

    uint32_t idx;
    while (xsk_ring_prod__reserve(dp->fq, (uint32_t)n, &idx) != (uint32_t)n) {
        if (!keep_running) return -1;
        usleep(10);
    }
    for (ssize_t i = 0; i < n; i++)
        *xsk_ring_prod__fill_addr(dp->fq, idx + (uint32_t)i) = d[i].addr;
    xsk_ring_prod__submit(dp->fq, (uint32_t)n);
    return 1;
}

static void run_datapath(struct dp *dp)
{
    struct pollfd pfd[2] = {
        { .fd = dp->xsk_fd,     .events = POLLIN },
        { .fd = dp->from_chain, .events = POLLIN },
    };

    while (keep_running) {
        int rc = drain_chain(dp);
        if (rc < 0) break;

        uint32_t idx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(dp->rx, BATCH_SIZE, &idx);
        if (rcvd == 0) {
            if (!rc) poll(pfd, 2, 100);   // 100 ms cap so Ctrl+C is noticed
            continue;
        }

        fifo_desc_t out[BATCH_SIZE];
        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc *d = xsk_ring_cons__rx_desc(dp->rx, idx + i);
            print_packet_info(xsk_umem__get_data(dp->umem, d->addr), d->addr, d->len, "RX");
            out[i] = (fifo_desc_t){ .addr = d->addr, .len = d->len };
        }
        xsk_ring_cons__release(dp->rx, rcvd);

        if (fifo_write_descs(dp->to_chain, out, rcvd) < 0) {
            perror("write to chain");
            break;
        }
    }
    keep_running = 0;
}

// ------------------------------------------------------------------- main
int main(int argc, char **argv)
{
    const char *conf_path = argc > 1 ? argv[1] : "chain.conf";
    struct config cfg;
    if (load_config(conf_path, &cfg)) return 1;
    if (argc > 2) snprintf(cfg.iface, sizeof(cfg.iface), "%s", argv[2]);

    int ifindex = (int)if_nametoindex(cfg.iface);
    if (!ifindex) { fprintf(stderr, "unknown interface %s\n", cfg.iface); return 1; }

    struct sigaction sa = { .sa_handler = on_signal };   // no SA_RESTART
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("Chain on %s: NIC", cfg.iface);
    for (int i = 0; i < cfg.n; i++) printf(" -> %s", cfg.nf[i]);
    printf(" -> %s   (steering TCP sport %u%s)\n", cfg.sink_stack ? "kernel stack" : "drop",
           cfg.port, cfg.port ? "" : " = everything");

    // ---- Shared UMEM: an anonymous memfd, passed to NFs by fd ----
    int umem_fd = memfd_create("flash_umem", MFD_CLOEXEC);
    if (umem_fd < 0 || ftruncate(umem_fd, (off_t)UMEM_BYTES) < 0) { perror("memfd"); return 1; }
    void *umem_area = mmap(NULL, UMEM_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, umem_fd, 0);
    if (umem_area == MAP_FAILED) { perror("mmap"); return 1; }

    // ---- One pipe per hop: p[0] .. p[n] ----
    struct hop p[MAX_CHAIN + 1];
    for (int i = 0; i <= cfg.n; i++) {
        int fds[2];
        if (pipe2(fds, O_CLOEXEC) < 0) { perror("pipe2"); return 1; }
        p[i].rd = fds[0];
        p[i].wr = fds[1];
        fifo_grow(p[i].wr);
    }

    // ---- Register NFs and wire them up ----
    int lfd = listen_monitor_sock();
    if (lfd < 0) return 1;
    int ok = wait_for_nfs(lfd, &cfg, p, umem_fd) == 0;
    close(lfd);
    unlink(MONITOR_SOCK);
    if (!ok) { printf("\nStopped before the chain was complete.\n"); return 1; }
    printf("Chain complete.\n");

    struct dp dp = {
        .umem = umem_area,
        .to_chain = p[0].wr,
        .from_chain = p[cfg.n].rd,
        .tap_fd = -1,
    };
    fcntl(dp.from_chain, F_SETFL, fcntl(dp.from_chain, F_GETFL) | O_NONBLOCK);

    if (cfg.sink_stack) {
        dp.tap_fd = tap_open(dp.tap_mac);
        if (dp.tap_fd < 0) return 1;
        printf("Re-injecting chain output into the kernel via %s.\n", TAP_NAME);
    }

    // ---- XDP program + steering filter ----
    struct bpf_object *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "failed to open xdp_kern.o\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "failed to load BPF object\n"); return 1; }

    int port_map_fd = bpf_object__find_map_fd_by_name(obj, "steer_port");
    uint32_t key = 0;
    if (bpf_map_update_elem(port_map_fd, &key, &cfg.port, 0)) { fprintf(stderr, "failed to set steer_port\n"); return 1; }

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_sock_prog"));
    int ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (ret) { fprintf(stderr, "failed to attach XDP to %s: %s\n", cfg.iface, strerror(-ret)); return 1; }
    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    // ---- AF_XDP on the shared UMEM ----
    struct xsk_umem *umem;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem_config ucfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };
    ret = xsk_umem__create(&umem, umem_area, UMEM_BYTES, &fq, &cq, &ucfg);
    if (ret) { fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret)); goto detach; }

    uint32_t idx;
    uint32_t nfill = xsk_prod_nb_free(&fq, NUM_FRAMES);
    if (xsk_ring_prod__reserve(&fq, nfill, &idx) != nfill) { fprintf(stderr, "fill reserve failed\n"); goto detach; }
    for (uint32_t i = 0; i < nfill; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = (uint64_t)i * FRAME_SIZE;
    xsk_ring_prod__submit(&fq, nfill);

    struct xsk_ring_cons rx;
    struct xsk_socket *xsk;
    struct xsk_socket_config scfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY,
    };
    ret = xsk_socket__create(&xsk, cfg.iface, 0, umem, &rx, NULL, &scfg);
    if (ret) { fprintf(stderr, "xsk_socket__create: %s\n", strerror(-ret)); goto detach; }

    dp.rx = &rx;
    dp.fq = &fq;
    dp.xsk_fd = xsk_socket__fd(xsk);
    int qid = 0;
    if (bpf_map_update_elem(xsks_map_fd, &qid, &dp.xsk_fd, 0)) { fprintf(stderr, "xsks_map update failed\n"); goto detach; }

    printf("Running. Try:  curl -4 http://example.com   Ctrl+C to stop.\n");
    run_datapath(&dp);

    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
detach:
    printf("\nDetaching XDP and shutting the chain down...\n");
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    close(p[0].wr);            // NF1 sees EOF, then NF2, ...
    close(p[cfg.n].rd);
    if (dp.tap_fd >= 0) close(dp.tap_fd);   // flash0 disappears
    bpf_object__close(obj);
    munmap(umem_area, UMEM_BYTES);
    close(umem_fd);
    return 0;
}
