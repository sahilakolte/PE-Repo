# AF_XDP Packet Sniffer Demo

A minimal demo of **AF_XDP**: a Linux socket type that lets a userspace
program receive raw packets almost directly from the NIC driver, bypassing
most of the normal kernel networking stack, for very high throughput.

## Files

| File          | Runs where     | Purpose                                             |
|---------------|----------------|------------------------------------------------------|
| `xdp_kern.c`  | Kernel (eBPF)  | Attached to the NIC's XDP hook; redirects packets to an AF_XDP socket |
| `xdp_user.c`  | Userspace      | Loads the eBPF program, creates the AF_XDP socket, reads packets, prints IPs |
| `Makefile`    | —              | Builds both pieces |

## Background: why AF_XDP?

Normal packet capture (e.g. a raw socket, or `libpcap`) has a packet travel:

```
NIC -> driver -> kernel network stack (routing, netfilter, sockets...) -> your program
```

That's a lot of kernel work per packet. **XDP (eXpress Data Path)** runs a
small, verified eBPF program at the very first point the driver hands off
a packet — before any of that stack runs. **AF_XDP** is a special socket
family that XDP can redirect packets into, so a packet goes:

```
NIC -> driver -> [eBPF program at XDP hook] -> AF_XDP socket -> your program
```

This skips almost the entire kernel stack, which is why AF_XDP is used
for things like software routers, DDoS scrubbers, and high-frequency
trading network taps — often tens of millions of packets/sec on one core.

## How the two halves work together

1. **`xdp_kern.c`** is compiled to BPF bytecode and loaded into the
   kernel. It's attached to a network interface's XDP hook. For every
   packet, it checks an `XSKMAP` (a map from RX-queue-index → AF_XDP
   socket) — if a userspace socket is registered for this queue, it calls
   `bpf_redirect_map()` to hand the raw frame to that socket instead of
   letting it continue up the stack. If nothing is registered, it returns
   `XDP_PASS` (normal processing).

2. **`xdp_user.c`** does the userspace setup:
   - Loads `xdp_kern.o` and attaches it to the chosen interface
     (`bpf_xdp_attach`).
   - Creates a **UMEM**: a large chunk of memory (`mmap`'d) shared between
     kernel and userspace, split into fixed-size frames. This is where
     packet bytes actually get written by the driver — no copy needed
     (in zero-copy mode).
   - Creates the **AF_XDP socket** bound to that UMEM, interface, and
     RX queue.
   - Registers the socket's file descriptor into the kernel program's
     `xsks_map`, so the redirect above knows where to send packets.
   - Seeds the **fill queue** — a ring buffer of empty UMEM frames the
     kernel is allowed to write incoming packets into.
   - Loops: polls the **RX ring** for newly-filled frames, parses each
     one's Ethernet header + IPv4 header, and prints source/destination
     IP and protocol. Then returns those frames to the fill queue so
     they can be reused for the next batch.

## The four rings (the "AF_XDP mental model")

AF_XDP moves buffer *ownership*, not bytes, between kernel and userspace
using four lock-free ring buffers over the shared UMEM:

- **Fill queue** (userspace → kernel): "here are empty frames you may fill"
- **RX ring** (kernel → userspace): "these frames now contain packets"
- **TX ring** (userspace → kernel): "please transmit these frames" (unused in this demo — it's receive-only)
- **Completion queue** (kernel → userspace): "these transmitted frames are free again"

This demo only uses the fill queue and RX ring, since it just receives
and prints — no packets are sent back out.

## Building

```
make
```

This produces `xdp_kern.o` (BPF bytecode) and `xdp_user` (the native
loader/receiver binary). Requires `clang`, and `libbpf-dev` +
`libxdp-dev` (provides `xsk.h`) on the build machine.

## Running

Needs root (loading a BPF program and attaching it to a live interface
requires elevated privileges):

```
sudo ./xdp_user <interface-name>
# e.g.
sudo ./xdp_user eth0
```

Sample output:

```
Attached in native driver mode.
Listening for packets on eth0 (queue 0)... Ctrl+C to stop.
[XDP] IPv4 packet  len=98   proto=1   192.168.1.10 -> 192.168.1.1
[XDP] IPv4 packet  len=74   proto=6   192.168.1.10 -> 142.250.premises
```

`proto` is the IP protocol number (1 = ICMP, 6 = TCP, 17 = UDP, ...).

Press **Ctrl+C** to stop; the program cleanly detaches the XDP program
and tears down the socket.

**Notes for the demo:**
- Run on a real NIC (e.g. `eth0`) or a `veth` pair with traffic flowing —
  the loopback interface (`lo`) doesn't reliably surface packets through
  the AF_XDP redirect path, since it isn't a real driver queue.
- If the NIC driver doesn't support native XDP, the program automatically
  falls back to **generic (SKB) mode**, which works on any interface but
  is slower since it runs later in the receive path.
- `bind_flags = XDP_COPY` is used here for portability (works on any NIC).
  Production zero-copy setups use `XDP_ZEROCOPY`, which needs driver
  support (e.g. Intel `i40e`/`ice`, Mellanox `mlx5`).
