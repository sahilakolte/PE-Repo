# AF_XDP Two-Process Packet Relay Demo

A demo of **AF_XDP** (a Linux socket type that lets a userspace program
receive raw packets almost directly from the NIC driver, bypassing most
of the normal kernel networking stack) extended to show packets flowing
between **two independent processes**, each with its own real AF_XDP
socket, linked by a virtual (`veth`) wire.

## Background: why AF_XDP?

Normal packet capture (e.g. a raw socket or `libpcap`) has a packet
travel:

```
NIC -> driver -> kernel network stack (routing, netfilter, sockets...) -> your program
```

**XDP (eXpress Data Path)** runs a small, verified eBPF program at the
very first point the NIC driver hands off a packet — before any of that
stack runs. **AF_XDP** is a socket family that XDP can redirect packets
into, so a packet instead goes:

```
NIC -> driver -> [eBPF program at XDP hook] -> AF_XDP socket -> your program
```

This skips almost the entire kernel stack, which is why AF_XDP is used
for things like software routers, DDoS scrubbers, and high-frequency
network taps.

## What this demo adds

The v1 version was a single process with one AF_XDP
socket. This version splits that into **two separate processes**
(`xdp_user1` and `xdp_user2`), each with its own UMEM and its own AF_XDP
socket, to show how a captured frame can be relayed from one AF_XDP
consumer to another.

Program1 doesn't hand program2 a pointer or a message — it **actually
transmits** each captured frame out a virtual network interface
(`veth1`), and program2 **actually receives** it on the other end
(`veth2`) via its own independent AF_XDP socket. The "relay" is a real
transmission over a real (virtual) wire, using only the standard AF_XDP
ring API.

## Files

| File             | Runs where     | Purpose                                                                 |
|------------------|----------------|--------------------------------------------------------------------------|
| `xdp_kern.c`     | Kernel (eBPF)  | Attached to a NIC/veth's XDP hook; redirects incoming frames into whichever AF_XDP socket is registered for that RX queue |
| `xdp_common.h`   | Userspace      | Code shared by both userspace programs: packet-printing helper + a hash function used to verify P1 and P2 see the *same* packet |
| `xdp_user1.c`    | Userspace      | Process #1: sniffs a real NIC via AF_XDP, prints each frame tagged `[P1]`, then re-transmits it out a veth interface |
| `xdp_user2.c`    | Userspace      | Process #2: an independent AF_XDP consumer on the other end of the veth pair; prints each frame tagged `[P2]` |
| `Makefile`       | —              | Builds both binaries and provides `veth-setup` / `run1` / `run2` helper targets |

### `xdp_kern.c` — the eBPF program

Runs once, but is loaded and attached **separately by each userspace
program** to whichever interface it owns:

- `xdp_user1` attaches it to the real NIC (e.g. `eth0` / `wlp0s20f3`).
- `xdp_user2` attaches it to its veth interface (`veth2`).

For every incoming packet it looks up an `XSKMAP` (`xsks_map`) keyed by
RX queue index. If a userspace AF_XDP socket is registered for that
queue, the packet is redirected straight to it (`bpf_redirect_map`). If
not, it falls through with `XDP_PASS` (normal kernel processing).

### `xdp_common.h` — shared helpers

- `now_ms()` — a monotonic millisecond timestamp, printed by both
  processes so you can visually line up when each process saw a given
  packet.
- `packet_hash()` — an FNV-1a hash computed over the full raw frame.
  Because both processes hash the exact same bytes and print the result,
  a matching `hash=` value in `[P1]`'s log and `[P2]`'s log is
  **proof** that the two processes handled the identical packet
  (not just two packets that happen to look similar), and a mismatch or
  missing entry would flag corruption or a dropped frame.
- `print_packet_info()` — parses the Ethernet + IPv4 headers and prints
  timestamp, hash, length, protocol, and source/destination IP,
  prefixed with a tag (`P1` or `P2`) so the two logs can be told apart.

### `xdp_user1.c` — process #1 (RX + relay)

Owns **two AF_XDP sockets sharing one UMEM**:

- `rxs` — bound to the real NIC, queue 0. This is the genuine AF_XDP
  receiver: `xdp_kern.o` redirects incoming frames into its RX ring.
- `txs` — bound to the veth interface (`veth1`), TX-only. No XDP program
  is needed here since this socket never receives.

Because both sockets share the same UMEM, a frame received on `rxs` can
be hand off to `txs`'s TX ring by copying only the **descriptor**
(address + length) — the packet bytes themselves never move. That's the
zero-copy part.

Per packet, the main loop:
1. Reads a frame from `rxs`'s RX ring (real AF_XDP receive from the
   NIC).
2. Prints it, tagged `[P1]`.
3. Places that same frame's descriptor onto `txs`'s TX ring and calls
   `sendto()` to kick the kernel into actually transmitting it out
   `veth1`.
4. Once the kernel reports the send complete (via `txs`'s completion
   ring), recycles that frame's address back into `rxs`'s fill queue so
   the NIC can reuse it.

### `xdp_user2.c` — process #2 (independent receiver)

A self-contained process with its own UMEM and its own AF_XDP socket,
bound to `veth2` — the other end of the veth pair. Structurally
identical to the original single-process demo: `xdp_kern.o` is attached
to `veth2`'s XDP hook, incoming frames are redirected into this
process's RX ring, and each one is printed tagged `[P2]`.

Every packet that `xdp_user1` transmits out `veth1` arrives here over
the veth wire and is picked up by real fill/RX rings — there is no
memory or IPC shared between the two processes at all.

### `Makefile`

- `make` / `make all` — builds `xdp_kern.o`, `xdp_user1`, `xdp_user2`.
- `make veth-setup` — creates the `veth1`/`veth2` pair (run once,
  requires root). `make veth-teardown` removes it.
- `make run1` — runs `xdp_user1` against `RX_IFACE` (defaults to
  `wlp0s20f3`; override with `make run1 RX_IFACE=eth0`), relaying to
  `veth1`.
- `make run2` — runs `xdp_user2` listening on `veth2`. Start in a
  second terminal, before or after `run1`.

## The four AF_XDP rings

AF_XDP moves buffer *ownership*, not bytes, between kernel and
userspace via four lock-free ring buffers over the shared UMEM:

- **Fill queue** (userspace → kernel): "here are empty frames you may
  fill."
- **RX ring** (kernel → userspace): "these frames now contain packets."
- **TX ring** (userspace → kernel): "please transmit these frames."
- **Completion queue** (kernel → userspace): "these transmitted frames
  are free again."

The original single-process demo only used the fill queue and RX ring
(pure receive). This demo additionally uses the TX ring and completion
queue in `xdp_user1`, since it both receives (from the NIC) and
transmits (to `xdp_user2` via veth).

## Building and running

Requires `clang`, `gcc`, and `libbpf-dev` + `libxdp-dev` (for
`xsk.h`).

```bash
make                      # builds xdp_kern.o, xdp_user1, xdp_user2
sudo make veth-setup      # creates veth1 <-> veth2 (run once)

# In one terminal:
sudo make run1 RX_IFACE=eth0     # or your real interface name

# In a second terminal:
sudo make run2
```

Generate some traffic on the real NIC (e.g. `ping` something), then
compare the two terminals' output — matching `hash=` values confirm the
same packet was seen by both processes:

```
[P1] t=1234567  hash=a3f19c2e  len=98   proto=1   192.168.1.10 -> 192.168.1.1
[P2] t=1234571  hash=a3f19c2e  len=98   proto=1   192.168.1.10 -> 192.168.1.1
```

Press **Ctrl+C** in either terminal to stop; each process cleanly
detaches its XDP program and tears down its socket/UMEM on exit.

