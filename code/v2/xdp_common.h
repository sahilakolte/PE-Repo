// xdp_common.h
// -----------------------------------------------------------------------
// Small bits shared by xdp_user1.c and xdp_user2.c.
//
// There is NO custom ring and NO shared-memory UMEM helper here anymore.
// Frame handoff between the two processes now happens entirely through
// *real* AF_XDP kernel rings:
//
//   program1's TX ring + completion ring  --(veth wire)-->  program2's
//   fill ring + RX ring
//
// i.e. program1 literally transmits each frame out a veth interface, and
// program2 literally receives it on the other end of that veth pair via
// its own AF_XDP socket. The only thing worth sharing between the two
// source files is this packet-printing helper.
// -----------------------------------------------------------------------

#ifndef XDP_COMMON_H
#define XDP_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#define NUM_FRAMES      4096u
#define FRAME_SIZE      4096u   // == XSK_UMEM__DEFAULT_FRAME_SIZE

// Millisecond timestamp since an arbitrary fixed point, monotonic clock.
// Printed by both processes so you can visually line up "same packet,
// seen a few hundred microseconds apart" between the two logs, alongside
// the packet's own 5-tuple (src/dst/proto/len) as the real correlation
// key -- the two processes don't share any memory or sequence counter.
static inline uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

// FNV-1a hash over the raw frame bytes. Used purely as a correlation key
// so you can confirm "this exact packet" showed up in both P1's and P2's
// logs, rather than eyeballing similar-looking 5-tuples. Any change to
// the bytes in transit (or a coincidentally similar but different
// packet) will produce a different hash.
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