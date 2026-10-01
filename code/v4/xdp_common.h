// xdp_common.h
// -----------------------------------------------------------------------
// Shared by xdp_user1.c and xdp_user2.c.
//
// A userspace analog of FLASH (SoCC '25) zero-copy packet redirection
// between co-located NFs.
//
//   1. Shared UMEM (POSIX shm, MAP_SHARED)
//      The packet bytes live here exactly once. xdp_user1 registers it as
//      a real AF_XDP UMEM; xdp_user2 just mmaps the same pages.
//
//   2. Two named pipes (FIFOs) carrying descriptors, never packet bytes
//        FIFO_P1_TO_P2 -- xdp_user1 writes {addr,len} for every packet it
//                         would otherwise put on its TX ring.
//        FIFO_P2_TO_P1 -- xdp_user2 writes {addr} back once it is done
//                         with a frame, so xdp_user1 can put it back on
//                         its fill queue (the job a TX completion ring
//                         would normally do).
//
// Why virtual addresses are not a problem:
//   The two processes mmap the UMEM at DIFFERENT virtual addresses, so a
//   raw pointer from P1 would be garbage in P2. We therefore never send
//   pointers -- `addr` is an OFFSET into the UMEM (exactly what AF_XDP
//   descriptors already use). Each side turns it into a pointer with its
//   own base:  pkt = my_umem_base + addr.
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
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#define NUM_FRAMES      4096u
#define FRAME_SIZE      4096u   // == XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      64u

// -----------------------------------------------------------------------
// POSIX shared memory (backing store for the UMEM)
// -----------------------------------------------------------------------
static inline void *posix_shm_attach(const char *name, size_t size)
{
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open"); return NULL; }
    // shm_open's mode is filtered by umask (usually -> 0644). If root
    // (xdp_user1) creates the object first, a non-root xdp_user2 could
    // not open it O_RDWR. Force 0666; failure (not owner) is harmless.
    (void)fchmod(fd, 0666);
    if (ftruncate(fd, (off_t)size) < 0) { perror("ftruncate"); close(fd); return NULL; }
    void *area = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (area == MAP_FAILED) { perror("mmap"); return NULL; }
    return area;
}

static inline void posix_shm_detach(void *area, size_t size, const char *name)
{
    munmap(area, size);
    shm_unlink(name);   // removes the name only; other process's mapping survives
}

#define SHARED_UMEM_NAME "/xdp_shared_umem"
#define UMEM_BYTES        ((size_t)NUM_FRAMES * FRAME_SIZE)

static inline void *shared_umem_create(void)  { return posix_shm_attach(SHARED_UMEM_NAME, UMEM_BYTES); }
static inline void  shared_umem_destroy(void *a) { posix_shm_detach(a, UMEM_BYTES, SHARED_UMEM_NAME); }

// -----------------------------------------------------------------------
// Named pipes (the veth / TX-ring replacement)
// -----------------------------------------------------------------------
#define FIFO_P1_TO_P2 "/tmp/xdp_p1_to_p2"   // packets:  P1 -> P2
#define FIFO_P2_TO_P1 "/tmp/xdp_p2_to_p1"   // recycling: P2 -> P1

// Fixed 16-byte record. Every write() is a whole number of these and is
// <= PIPE_BUF, so the kernel guarantees it is atomic; every read() asks
// for a multiple of 16 bytes. Together that means a reader never sees a
// torn descriptor.
typedef struct {
    uint64_t addr;  // OFFSET into the shared UMEM (not a pointer!)
    uint32_t len;   // frame length; 0 on the return pipe
    uint32_t _pad;
} fifo_desc_t;

_Static_assert(sizeof(fifo_desc_t) == 16, "fifo_desc_t must be 16 bytes");
_Static_assert(BATCH_SIZE * sizeof(fifo_desc_t) <= PIPE_BUF,
               "a batch must fit in one atomic pipe write");

// Create the FIFO if needed (either process may start first) and make it
// world read/write so root-P1 and non-root-P2 can both open it.
static inline int fifo_ensure(const char *path)
{
    if (mkfifo(path, 0666) < 0 && errno != EEXIST) {
        perror("mkfifo");
        return -1;
    }
    struct stat st;
    if (stat(path, &st) < 0) { perror("stat fifo"); return -1; }
    if (!S_ISFIFO(st.st_mode)) {
        fprintf(stderr, "%s exists but is not a FIFO (remove it)\n", path);
        return -1;
    }
    (void)chmod(path, 0666);   // defeat umask; harmless if not owner
    return 0;
}

// Opens a FIFO end. A blocking open() of a FIFO waits until the other
// end is opened by the peer process, so this is also the rendezvous
// point between xdp_user1 and xdp_user2.
// IMPORTANT: both programs must open the two FIFOs in the SAME order
// (P1_TO_P2 first, then P2_TO_P1) or they deadlock.
static inline int fifo_open(const char *path, int flags)
{
    if (fifo_ensure(path) < 0)
        return -1;
    // Not retried on EINTR on purpose, so Ctrl+C can abort the wait
    // (the programs install SIGINT without SA_RESTART).
    int fd = open(path, flags);
    if (fd < 0)
        perror(path);
    return fd;
}

// Write n descriptors. n <= BATCH_SIZE => one atomic write. Returns 0 on
// success, -1 on error (EPIPE means the reader went away).
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
// Returns: >0 number of descriptors, 0 on EOF (peer closed its end),
//          -1 on error (errno == EAGAIN for "nothing yet" on O_NONBLOCK,
//          errno == EINTR if interrupted by a signal).
static inline ssize_t fifo_read_descs(int fd, fifo_desc_t *d, size_t max)
{
    ssize_t r = read(fd, d, max * sizeof(*d));
    if (r <= 0)
        return r;
    // Can't happen given atomic 16-byte-multiple writes, but be safe:
    // finish a partially read record.
    size_t rem = (size_t)r % sizeof(*d);
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

// Make the pipe big enough to hold every frame's descriptor at once, so
// P1's write can never block (there are only NUM_FRAMES frames, hence at
// most NUM_FRAMES descriptors in flight). Linux-only, best effort.
static inline void fifo_grow(int fd)
{
#ifdef F_SETPIPE_SZ
    int want = (int)(NUM_FRAMES * sizeof(fifo_desc_t));
    if (fcntl(fd, F_SETPIPE_SZ, want) < 0)
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

// FNV-1a over the frame bytes: a correlation key between P1's and P2's logs.
static inline uint32_t packet_hash(const uint8_t *pkt, uint32_t len)
{
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < len; i++) { h ^= pkt[i]; h *= 16777619u; }
    return h;
}

// Prints the UMEM offset and this process's virtual address for the
// frame. The offsets match across P1/P2 while the virtual addresses
// differ -- same physical bytes, different mappings.
static inline void print_packet_info(const uint8_t *pkt, uint64_t addr,
                                     uint32_t len, const char *tag)
{
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
        return;
    const struct ethhdr *eth = (const struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return;

    const struct iphdr *iph = (const struct iphdr *)(pkt + sizeof(struct ethhdr));
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &iph->daddr, dst_str, sizeof(dst_str));

    printf("[%s] t=%-8llu off=0x%08llx va=%p hash=%08x len=%-4u proto=%-2u  %s -> %s\n",
           tag, (unsigned long long)now_ms(), (unsigned long long)addr,
           (const void *)pkt, packet_hash(pkt, len), len, iph->protocol,
           src_str, dst_str);
}

#endif // XDP_COMMON_H
