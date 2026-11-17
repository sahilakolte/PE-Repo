// xdp_common.h
// -----------------------------------------------------------------------
// Shared by monitor.c and every NF (through nf_lib.h).
//
// A userspace analog of FLASH (SoCC '25) NF chaining:
//
//   * ONE shared UMEM (a memfd). The packet bytes live here exactly once.
//     The monitor registers it as its AF_XDP UMEM; every NF mmaps the
//     same pages from the fd the monitor hands it.
//
//   * A chain of anonymous pipes carrying 16-byte DESCRIPTORS, never
//     packet bytes:
//
//        monitor --p0--> NF1 --p1--> NF2 --p2--> ... --pN--> monitor
//
//     The monitor creates all the pipes and gives each NF exactly two
//     ends: "in" and "out". An NF never learns what is on the other end.
//     This is the job FLASH's per-socket `next` sysfs file does.
//
//   * A Unix domain socket (MONITOR_SOCK). NFs connect, say their name,
//     and get back {umem fd, in fd, out fd} via SCM_RIGHTS -- the same
//     way FLASH NFs get their UMEM fd from the FLASH monitor.
// -----------------------------------------------------------------------

#ifndef XDP_COMMON_H
#define XDP_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>     // PIPE_BUF
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define NUM_FRAMES      4096u
#define FRAME_SIZE      4096u   // == XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      64u
#define UMEM_BYTES      ((size_t)NUM_FRAMES * FRAME_SIZE)

#define MONITOR_SOCK    "/tmp/flash_monitor.sock"
#define NF_NAME_MAX     32
#define MAX_CHAIN       16

// -----------------------------------------------------------------------
// Descriptor that travels along the chain
// -----------------------------------------------------------------------
typedef struct {
    uint64_t addr;   // OFFSET into the shared UMEM (never a pointer)
    uint32_t len;    // frame length
    uint32_t _pad;   // keeps the record 16 bytes
} fifo_desc_t;

_Static_assert(sizeof(fifo_desc_t) == 16, "fifo_desc_t must be 16 bytes");
_Static_assert(BATCH_SIZE * sizeof(fifo_desc_t) <= PIPE_BUF,
               "a batch must fit in one atomic pipe write");

// -----------------------------------------------------------------------
// Monitor <-> NF control messages (over SOCK_SEQPACKET, one per message)
// -----------------------------------------------------------------------
struct nf_hello {                 // NF -> monitor
    char name[NF_NAME_MAX];
};

struct nf_welcome {               // monitor -> NF (+ 3 fds on success)
    int32_t  status;              // 0 = ok, otherwise see msg
    uint32_t _pad;
    uint64_t umem_bytes;
    char     msg[96];
};

#define WELCOME_NFDS 3            // fds[0]=umem, fds[1]=in, fds[2]=out

// Send one message plus nfds file descriptors (SCM_RIGHTS).
static inline int uds_send(int sock, const void *buf, size_t len,
                           const int *fds, int nfds)
{
    struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
    union { char b[CMSG_SPACE(sizeof(int) * WELCOME_NFDS)]; struct cmsghdr a; } u;
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };

    if (nfds > 0) {
        memset(&u, 0, sizeof(u));
        msg.msg_control = u.b;
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfds);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
        memcpy(CMSG_DATA(c), fds, sizeof(int) * (size_t)nfds);
    }
    return sendmsg(sock, &msg, MSG_NOSIGNAL) < 0 ? -1 : 0;
}

// Receive one message and up to WELCOME_NFDS fds. Returns bytes read.
static inline ssize_t uds_recv(int sock, void *buf, size_t len,
                               int *fds, int *nfds)
{
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    union { char b[CMSG_SPACE(sizeof(int) * WELCOME_NFDS)]; struct cmsghdr a; } u;
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.b, .msg_controllen = sizeof(u.b) };
    *nfds = 0;
    ssize_t r = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    if (r < 0) return r;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            int n = (int)((c->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            if (n > WELCOME_NFDS) n = WELCOME_NFDS;
            memcpy(fds, CMSG_DATA(c), sizeof(int) * (size_t)n);
            *nfds = n;
        }
    }
    return r;
}

// -----------------------------------------------------------------------
// Descriptor pipes
// -----------------------------------------------------------------------

// Write n descriptors. n <= BATCH_SIZE => one atomic write.
// Returns 0 on success, -1 on error (EPIPE: the reader went away).
static inline int fifo_write_descs(int fd, const fifo_desc_t *d, size_t n)
{
    const uint8_t *p = (const uint8_t *)d;
    size_t left = n * sizeof(*d);
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        left -= (size_t)w;
    }
    return 0;
}

// Read up to max descriptors.
// Returns: >0 number of descriptors, 0 on EOF (upstream closed),
//          -1 on error (EAGAIN on O_NONBLOCK, EINTR on a signal).
static inline ssize_t fifo_read_descs(int fd, fifo_desc_t *d, size_t max)
{
    ssize_t r = read(fd, d, max * sizeof(*d));
    if (r <= 0)
        return r;
    size_t rem = (size_t)r % sizeof(*d);   // can't happen (atomic writes)
    if (rem) {
        uint8_t *p = (uint8_t *)d + r;
        size_t need = sizeof(*d) - rem;
        while (need) {
            ssize_t x = read(fd, p, need);
            if (x > 0) { p += x; need -= (size_t)x; r += x; continue; }
            if (x == 0) return 0;
            if (errno != EINTR && errno != EAGAIN) return -1;
        }
    }
    return r / (ssize_t)sizeof(*d);
}

// Big enough for every frame's descriptor, so no write in the chain can
// ever block (only NUM_FRAMES descriptors exist). Best effort.
static inline void fifo_grow(int fd)
{
#ifdef F_SETPIPE_SZ
    if (fcntl(fd, F_SETPIPE_SZ, (int)(NUM_FRAMES * sizeof(fifo_desc_t))) < 0)
        perror("F_SETPIPE_SZ (continuing with default size)");
#else
    (void)fd;
#endif
}

// -----------------------------------------------------------------------
// Logging helpers
// -----------------------------------------------------------------------
static inline uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

// One line per packet: UMEM offset (same in every process), this
// process's virtual address (different in every process), 5-tuple, TCP
// flags, and the HTTP status line if the payload starts with one.
static inline void print_packet_info(const uint8_t *pkt, uint64_t addr,
                                     uint32_t len, const char *tag)
{
    printf("[%-4s] t=%-8llu off=0x%08llx va=%p len=%-4u ",
           tag, (unsigned long long)now_ms(), (unsigned long long)addr,
           (const void *)pkt, len);

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) { printf("short\n"); return; }
    const struct ethhdr *eth = (const struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        printf("ethertype=0x%04x\n", ntohs(eth->h_proto));
        return;
    }

    const struct iphdr *iph = (const struct iphdr *)(pkt + sizeof(*eth));
    uint32_t ihl = iph->ihl * 4u;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));

    const uint8_t *l4 = pkt + sizeof(*eth) + ihl;
    uint32_t l4_len = len - (uint32_t)sizeof(*eth) - ihl;
    if (ihl < 20 || sizeof(*eth) + ihl > len) { printf("bad IP header\n"); return; }

    if (iph->protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
        const struct tcphdr *th = (const struct tcphdr *)l4;
        uint32_t thl = th->doff * 4u;
        printf("TCP %s:%u -> %s:%u [%s%s%s%s%s]", src, ntohs(th->source),
               dst, ntohs(th->dest), th->syn ? "S" : "", th->ack ? "A" : "",
               th->psh ? "P" : "", th->fin ? "F" : "", th->rst ? "R" : "");
        if (thl >= 20 && thl < l4_len) {
            const char *pl = (const char *)l4 + thl;
            uint32_t pl_len = l4_len - thl;
            printf(" payload=%u", pl_len);
            if (pl_len >= 5 && memcmp(pl, "HTTP/", 5) == 0) {
                uint32_t n = 0;
                while (n < pl_len && n < 40 && pl[n] != '\r' && pl[n] != '\n') n++;
                printf(" \"%.*s\"", (int)n, pl);
            }
        }
        printf("\n");
    } else if (iph->protocol == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
        const struct udphdr *uh = (const struct udphdr *)l4;
        printf("UDP %s:%u -> %s:%u\n", src, ntohs(uh->source), dst, ntohs(uh->dest));
    } else {
        printf("proto=%u %s -> %s\n", iph->protocol, src, dst);
    }
}

#endif // XDP_COMMON_H
