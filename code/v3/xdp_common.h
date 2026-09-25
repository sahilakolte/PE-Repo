// xdp_common.h
// -----------------------------------------------------------------------
// Shared by xdp_user1.c and xdp_user2.c.
//
// This is a userspace-level analog of FLASH (SoCC '25) "zero-copy packet
// redirection" between co-located NFs -- see the design note at the top
// of xdp_user1.c for the full picture and an honest account of where
// this differs from what FLASH actually does (FLASH patches the Linux
// kernel's AF_XDP subsystem directly; this demo does not touch the
// kernel at all, and instead emulates the redirect hop one layer up, in
// userspace shared memory).
//
// Two shared-memory facilities live here:
//
//   1. shared_umem_create() / shared_umem_destroy()
//      A POSIX shared-memory region (shm_open + mmap MAP_SHARED) that
//      backs the UMEM. Only xdp_user1 ever registers a real AF_XDP UMEM
//      on top of it (xsk_umem__create) -- xdp_user2 just mmaps the same
//      bytes and reads them directly, so a packet's payload is stored
//      exactly ONCE in physical memory, for its entire lifetime in this
//      pipeline.
//
//   2. redirect_shm_create() / redirect_shm_destroy(), spsc_push()/pop()
//      A second shared-memory region holding two lock-free
//      single-producer single-consumer descriptor rings:
//        p1_to_p2 -- xdp_user1 pushes {addr,len} for every packet it
//                    would otherwise have "transmitted". This *is* the
//                    replacement for the veth wire: only an 8+4 byte
//                    descriptor crosses over, never the packet bytes.
//        p2_to_p1 -- once xdp_user2 is done with a frame, it pushes the
//                    address back here so xdp_user1 can recycle it into
//                    its AF_XDP fill queue (standing in for what a real
//                    TX completion ring would normally do).
//      In xdp_user1, a dedicated pthread -- named ksoftirqd_thread to
//      match the role it plays -- is the only thing that touches these
//      rings on the P1 side: it drains real received frames from the
//      genuine kernel AF_XDP RX ring and performs the push/pop against
//      these shared rings, exactly where FLASH's actual kernel code
//      (running under ksoftirqd) would perform the equivalent ring
//      surgery on real AF_XDP rings.
// -----------------------------------------------------------------------

#ifndef XDP_COMMON_H
#define XDP_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#define NUM_FRAMES      4096u
#define FRAME_SIZE      4096u   // == XSK_UMEM__DEFAULT_FRAME_SIZE

// -----------------------------------------------------------------------
// Generic POSIX shared-memory attach/detach, used for both the UMEM and
// the redirect-ring region below. Safe to call from both processes in
// either start order: shm_open(O_CREAT) returns the existing object if
// one is already there, and ftruncate to the same size on an
// already-correctly-sized object is a no-op. A freshly created POSIX shm
// object reads as all-zero, so callers don't need to memset it.
// -----------------------------------------------------------------------
static inline void *posix_shm_attach(const char *name, size_t size)
{
    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open"); return NULL; }
    if (ftruncate(fd, (off_t)size) < 0) { perror("ftruncate"); close(fd); return NULL; }
    void *area = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd); // fd not needed once mmap'd
    if (area == MAP_FAILED) { perror("mmap"); return NULL; }
    return area;
}

// Unmaps this process's view and best-effort removes the shm name.
// shm_unlink only removes the *name* -- it doesn't disturb the other
// process's still-open mapping -- so it's safe to call from both
// processes on exit regardless of which shuts down first; whichever
// call loses the race just fails harmlessly with ENOENT.
static inline void posix_shm_detach(void *area, size_t size, const char *name)
{
    munmap(area, size);
    shm_unlink(name);
}

// ---- 1. Shared UMEM (packet storage, single copy) ----------------------

#define SHARED_UMEM_NAME "/xdp_shared_umem"
#define UMEM_BYTES        ((size_t)NUM_FRAMES * FRAME_SIZE)

static inline void *shared_umem_create(void)
{
    return posix_shm_attach(SHARED_UMEM_NAME, UMEM_BYTES);
}

static inline void shared_umem_destroy(void *area)
{
    posix_shm_detach(area, UMEM_BYTES, SHARED_UMEM_NAME);
}

// ---- 2. Shared descriptor rings (the veth replacement) ------------------

#define REDIR_RING_CAPACITY 4096u                       // must be power of two
#define REDIR_RING_MASK     (REDIR_RING_CAPACITY - 1u)

typedef struct {
    uint64_t addr;  // offset into the shared UMEM
    uint32_t len;   // frame length; unused (0) on the p2_to_p1 return ring
} redir_desc_t;

// Classic lockless SPSC ring: one producer, one consumer, each touching
// only their own index most of the time. prod/cons are pinned to
// separate cache lines so the producer and consumer don't ping-pong the
// same cache line between cores on every push/pop -- the same concern
// FLASH calls out (Figure 7 / Challenge 1) when it extends these rings
// to multi-producer/multi-consumer. We don't need MP/MC here because
// each ring in this demo has exactly one real producer and one real
// consumer (P1's ksoftirqd_thread only ever pushes to p1_to_p2 and pops
// from p2_to_p1; P2 only does the reverse), so plain SPSC is sufficient
// and keeps this readable.
typedef struct {
    _Atomic uint32_t prod __attribute__((aligned(64)));
    _Atomic uint32_t cons __attribute__((aligned(64)));
    redir_desc_t entries[REDIR_RING_CAPACITY];
} spsc_desc_ring_t;

typedef struct {
    spsc_desc_ring_t p1_to_p2; // NF1 "TX" -> NF2 "RX": in-flight packets
    spsc_desc_ring_t p2_to_p1; // frame recycling: NF2 -> NF1's fill queue
} redirect_shm_t;

#define REDIRECT_SHM_NAME "/xdp_redirect_shm"

static inline redirect_shm_t *redirect_shm_create(void)
{
    return (redirect_shm_t *)posix_shm_attach(REDIRECT_SHM_NAME, sizeof(redirect_shm_t));
}

static inline void redirect_shm_destroy(redirect_shm_t *shm)
{
    posix_shm_detach(shm, sizeof(redirect_shm_t), REDIRECT_SHM_NAME);
}

// Returns 1 on success, 0 if the ring is full (backpressure -- caller
// should stop pulling more work from upstream until there's room, the
// same idea as FLASH's backpressure detection in §4.4).
static inline int spsc_push(spsc_desc_ring_t *r, uint64_t addr, uint32_t len)
{
    uint32_t p = atomic_load_explicit(&r->prod, memory_order_relaxed);
    uint32_t c = atomic_load_explicit(&r->cons, memory_order_acquire);
    if (p - c >= REDIR_RING_CAPACITY)
        return 0;
    r->entries[p & REDIR_RING_MASK].addr = addr;
    r->entries[p & REDIR_RING_MASK].len  = len;
    atomic_store_explicit(&r->prod, p + 1, memory_order_release);
    return 1;
}

// Returns 1 and fills *addr/*len on success, 0 if the ring is empty.
// len may be NULL (the p2_to_p1 return ring only carries addresses).
static inline int spsc_pop(spsc_desc_ring_t *r, uint64_t *addr, uint32_t *len)
{
    uint32_t c = atomic_load_explicit(&r->cons, memory_order_relaxed);
    uint32_t p = atomic_load_explicit(&r->prod, memory_order_acquire);
    if (c == p)
        return 0;
    *addr = r->entries[c & REDIR_RING_MASK].addr;
    if (len) *len = r->entries[c & REDIR_RING_MASK].len;
    atomic_store_explicit(&r->cons, c + 1, memory_order_release);
    return 1;
}

// -----------------------------------------------------------------------
// Millisecond timestamp since an arbitrary fixed point, monotonic clock.
// Printed by both processes so you can visually line up "same packet,
// seen a few hundred microseconds apart" between the two logs, alongside
// the packet's own 5-tuple (src/dst/proto/len) as the real correlation
// key.
static inline uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

// FNV-1a hash over the raw frame bytes. Used purely as a correlation key
// so you can confirm "this exact packet" showed up in both P1's and P2's
// logs. Because P1 and P2 now read the very same physical bytes (no
// copy anywhere in the pipeline), a matching hash here is a direct,
// literal proof of zero-copy, not just "these look like the same
// packet" -- it IS the same 4 KiB frame in memory, observed twice.
static inline uint32_t packet_hash(const uint8_t *pkt, uint32_t len)
{
    uint32_t h = 2166136261u; // FNV offset basis
    for (uint32_t i = 0; i < len; i++) {
        h ^= pkt[i];
        h *= 16777619u; // FNV prime
    }
    return h;
}

static inline void print_packet_info(const uint8_t *pkt, uint32_t len, const char *tag)
{
    if (len < sizeof(struct ethhdr))
        return;

    const struct ethhdr *eth = (const struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return;

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
        return;

    const struct iphdr *iph = (const struct iphdr *)(pkt + sizeof(struct ethhdr));

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    struct in_addr src = { .s_addr = iph->saddr };
    struct in_addr dst = { .s_addr = iph->daddr };

    strncpy(src_str, inet_ntoa(src), sizeof(src_str) - 1); src_str[sizeof(src_str) - 1] = '\0';
    strncpy(dst_str, inet_ntoa(dst), sizeof(dst_str) - 1); dst_str[sizeof(dst_str) - 1] = '\0';

    // Hash the whole frame (Ethernet header onward) so the key reflects
    // the exact bytes that were sent, not just the IP header fields.
    uint32_t hash = packet_hash(pkt, len);

    printf("[%s] t=%-8llu hash=%08x len=%-4u proto=%-2u  %s -> %s\n",
           tag, (unsigned long long)now_ms(), hash, len, iph->protocol, src_str, dst_str);
}

#endif // XDP_COMMON_H
