# AF_XDP Two-Process Packet Relay Demo

## Files

| File             | Runs where     | Purpose                                                                 |
|------------------|----------------|--------------------------------------------------------------------------|
| `xdp_kern.c`     | Kernel (eBPF)  | Attached to the real NIC's XDP hook by `xdp_user1`; redirects incoming frames into its AF_XDP socket |
| `xdp_common.h`   | Userspace      | Shared UMEM setup, the SPSC descriptor rings that replace the veth wire, packet-printing helper, and the correlation hash |
| `xdp_user1.c`    | Userspace      | The only real AF_XDP consumer. Receives on the NIC via a main-thread-spawned `ksoftirqd_thread`, which redirects descriptors to `xdp_user2` via shared memory |
| `xdp_user2.c`    | Userspace      | A plain shared-memory consumer — no socket, no NIC, no root — that reads redirected packets straight out of the shared UMEM |
| `Makefile`       | —              | Builds both binaries and provides `run1` / `run2` helper targets |

### `xdp_kern.c` — the eBPF program

Unchanged. Loaded and attached by `xdp_user1` only — `xdp_user2` no
longer touches AF_XDP/XDP at all, so it doesn't need this.

For every incoming packet it looks up an `XSKMAP` (`xsks_map`) keyed by
RX queue index. If a userspace AF_XDP socket is registered for that
queue, the packet is redirected straight to it (`bpf_redirect_map`). If
not, it falls through with `XDP_PASS` (normal kernel processing).

### `xdp_common.h` — shared helpers

- `shared_umem_create()` / `shared_umem_destroy()` — POSIX shared
  memory backing the packet buffer region, so `xdp_user1` and
  `xdp_user2` see the exact same physical bytes.
- `redirect_shm_create()` / `redirect_shm_destroy()`,
  `spsc_push()` / `spsc_pop()` — two lock-free SPSC rings in a second
  shared-memory region: `p1_to_p2` carries in-flight packet
  descriptors (the veth replacement), `p2_to_p1` returns frames for
  recycling into `xdp_user1`'s fill queue.
- `now_ms()` — a monotonic millisecond timestamp, printed by both
  processes so you can visually line up when each process saw a given
  packet.
- `packet_hash()` — an FNV-1a hash computed over the full raw frame.
  Because both processes now read the *same physical bytes* rather
  than a copy relayed over a wire, a matching `hash=` value in `[P1]`'s
  log and `[P2]`'s log is a direct, literal proof of zero-copy, not
  just "these look like the same packet."
- `print_packet_info()` — parses the Ethernet + IPv4 headers and prints
  timestamp, hash, length, protocol, and source/destination IP,
  prefixed with a tag (`P1` or `P2`).

### `xdp_user1.c` — the real AF_XDP receiver

Owns the one real AF_XDP socket in the whole pipeline, bound to the
real NIC (`rx_ifname`), with its UMEM backed by shared memory.

A dedicated `ksoftirqd_thread` — spawned once at startup, running for
the process's whole lifetime — is the only code that touches the real
RX ring or the redirect rings:

1. Drains frames `xdp_user2` has returned (`p2_to_p1`) back into the
   fill queue, so the NIC can reuse them.
2. Peeks the real RX ring for newly arrived frames, prints each one
   tagged `[P1]`, and pushes its descriptor onto `p1_to_p2`. If that
   ring is momentarily full, the frame is dropped in this demo rather
   than queued for retry — the natural backpressure point FLASH also
   calls out in §4.4.

`main()` itself does nothing after spawning the thread but wait for
`SIGINT`, matching how the real kernel `ksoftirqd` thread runs
independently of any userspace application thread.

### `xdp_user2.c` — the shared-memory consumer

No socket, no NIC binding, no XDP program, no elevated privileges.
Attaches to the same two shared-memory regions `xdp_user1` created, and
loops: pop a descriptor from `p1_to_p2`, read the packet directly out
of the shared UMEM and print it tagged `[P2]`, then push the address
onto `p2_to_p1` so `xdp_user1` can recycle the frame.

### `Makefile`

- `make` / `make all` — builds `xdp_kern.o`, `xdp_user1`, `xdp_user2`.
  Note `xdp_user2` links against neither `libbpf` nor `libxdp` — it
  genuinely doesn't need them anymore.
- `make run1` — runs `xdp_user1` against `RX_IFACE` (defaults to
  `wlp0s20f3`; override with `make run1 RX_IFACE=eth0`). Needs root
  (real AF_XDP socket + loading a BPF program).
- `make run2` — runs `xdp_user2`, no `sudo` needed. Start in a second
  terminal, before or after `run1`.
- `make clean-shm` — removes `/dev/shm/xdp_shared_umem` and
  `/dev/shm/xdp_redirect_shm` by hand, in case a process was killed
  before it could unlink them itself.

## Building and running

Requires `clang`, `gcc`, and `libbpf-dev` + `libxdp-dev` (for
`xsk.h`) — only for building `xdp_user1`; `xdp_user2` has no such
dependency.

```bash
make                          # builds xdp_kern.o, xdp_user1, xdp_user2

# In one terminal:
sudo make run1 RX_IFACE=eth0  # or your real interface name

# In a second terminal (no sudo needed):
make run2
```

Generate some traffic on the real NIC (e.g. `ping` something), then
compare the two terminals' output — matching `hash=` values now prove
the two processes read the identical physical frame, not just similar
packets:

```
[P1] t=1234567  hash=a3f19c2e  len=98   proto=1   192.168.1.10 -> 192.168.1.1
[P2] t=1234571  hash=a3f19c2e  len=98   proto=1   192.168.1.10 -> 192.168.1.1
```

Press **Ctrl+C** in either terminal to stop.
