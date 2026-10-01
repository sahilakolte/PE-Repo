# AF_XDP zero-copy redirect over a named pipe

A small userspace experiment inspired by **FLASH (SoCC '25)**, which redirects packets between co-located network functions without copying them.

Program 1 receives packets from a real NIC with AF_XDP into a **shared UMEM**. It doesn't put them on a TX ring and send them through a veth pair, because that copies each packet into the second program's UMEM. Instead it writes a small **descriptor** (`{offset, len}`) into a **named pipe**. Program 2 reads the descriptor and reads the packet **in place** from the same shared memory. There is no second copy of the packet.

```
             NIC (e.g. wlp0s20f3)
                    │  XDP hook: xdp_kern.o → bpf_redirect_map(xsks_map)
                    ▼
 ┌────────────────────────────────┐           ┌────────────────────────────┐
 │ xdp_user1  (root)              │           │ xdp_user2  (no root)       │
 │  AF_XDP socket, RX ring        │  {off,len}│                            │
 │  fill queue  ◄──────────┐      │ ───────►  │  read /tmp/xdp_p1_to_p2    │
 │                         │      │  FIFO     │  pkt = my_base + off       │
 │                         └──────│ ◄───────  │  write /tmp/xdp_p2_to_p1   │
 └───────────────┬────────────────┘  {off}    └──────────────┬─────────────┘
                 │                   FIFO                    │
                 |                                           |
                 └──────► /dev/shm/xdp_shared_umem  ◄────────┘
                          (16 MiB, 4096 × 4 KiB frames,
                           packet bytes stored once)
```

## Files

| File | Purpose |
|---|---|
| `xdp_kern.c` | eBPF program on the NIC's XDP hook. It redirects every packet on queue 0 to the AF_XDP socket in `xsks_map`. |
| `xdp_user1.c` | The real AF_XDP receiver. It loads and attaches `xdp_kern.o`, creates the UMEM on shared memory, receives packets, writes descriptors to the forward pipe, and recycles returned frames into the fill queue. |
| `xdp_user2.c` | The consumer. It maps the shared UMEM, reads descriptors from the forward pipe, processes packets in place, and writes offsets back on the return pipe. It uses no AF_XDP and doesn't need root. |
| `xdp_common.h` | Shared code: POSIX shared-memory helpers, FIFO helpers, the descriptor format, and logging. |
| `Makefile` | Build, run and cleanup targets. |

## How it works

### Shared UMEM
`shm_open("/xdp_shared_umem")` plus `mmap(MAP_SHARED)`. Program 1 registers this region as its AF_XDP UMEM (`xsk_umem__create`). Program 2 only maps the same pages.

### Named pipes (FIFOs)
Both programs are independent processes, not a parent and child. They meet through two FIFOs in `/tmp`:

| FIFO | Direction | Contents | Role |
|---|---|---|---|
| `/tmp/xdp_p1_to_p2` | P1 → P2 | `{offset, len}` | Replaces the TX ring and veth "wire" |
| `/tmp/xdp_p2_to_p1` | P2 → P1 | `{offset}` | Replaces the TX completion ring, so frames go back to P1's fill queue |

Whichever program starts first creates the FIFOs with `mkfifo`. A blocking `open()` on a FIFO waits for the other end to be opened, so the two programs can start in any order. Both open the pipes in the same order (forward first, then return) to avoid a deadlock.

### Why offsets, not pointers
Each process maps the shared memory at a **different virtual address**, so a pointer from P1 would be meaningless in P2. The descriptor carries the frame's **offset into the UMEM**, which is what AF_XDP descriptors already use. Each process builds its own pointer:

```c
uint8_t *pkt = (uint8_t *)my_umem_base + desc.addr;
```

The logs print both values: `off=` matches across the two programs and `va=` differs.

### Descriptor format
```c
typedef struct { uint64_t addr; uint32_t len; uint32_t _pad; } fifo_desc_t;  // 16 bytes
```
Descriptors are written in batches of up to 64 (1 KiB, which is ≤ `PIPE_BUF`). The kernel guarantees such a write is **atomic**, and reads always request a multiple of 16 bytes, so a reader never sees half a descriptor.

### Frame lifecycle
1. At startup, P1 gives all 4096 frames to the kernel through the fill queue.
2. The kernel writes a packet into a frame and posts `{addr, len}` on the RX ring.
3. P1 reads the RX ring, logs the packet, and writes the descriptor to `xdp_p1_to_p2`.
4. P2 reads the descriptor, processes the packet at `base + addr`, and writes `addr` to `xdp_p2_to_p1`.
5. P1 reads the returned address and puts the frame back on the fill queue.

P1 enlarges the forward pipe (`F_SETPIPE_SZ`) to hold all 4096 descriptors, so its writes can't block. P1 sleeps in `poll()` on the AF_XDP socket and the return pipe. P2 waits in a blocking `read()`. Neither program busy-waits.

## Requirements

- Linux with AF_XDP support
- `clang` (for the BPF object) and `gcc`
- `libbpf` and `libxdp` development packages, for example on Debian/Ubuntu:
  ```sh
  sudo apt install clang libbpf-dev libxdp-dev
  ```
- Root for `xdp_user1` only

## Build

```sh
make            # builds xdp_kern.o, xdp_user1, xdp_user2
```

## Run

Use two terminals, in either order:

```sh
# Terminal 1 (root): attach to the NIC
make run1                       # default interface wlp0s20f3
make run1 RX_IFACE=eth0         # or pick another interface

# Terminal 2 (normal user)
make run2
```

Example output (the same packet seen by both programs):

```
[P1] t=406111 off=0x00000100 va=0x7fefd3400100 hash=2b00a2df len=60 proto=17 10.0.0.1 -> 10.0.0.254
[P2] t=406111 off=0x00000100 va=0x7f60b1e00100 hash=2b00a2df len=60 proto=17 10.0.0.1 -> 10.0.0.254
```

The **same offset and hash with different virtual addresses** shows both processes read the same physical bytes.

## Stop and clean up

- Press **Ctrl+C** in either terminal. When one program closes its pipe, the other sees end-of-file and exits too. P1 detaches the XDP program on the way out.
- After a crash or `kill -9`:
  ```sh
  make clean-ipc   # removes /dev/shm/xdp_shared_umem and the two FIFOs
  make clean       # removes build outputs
  ```
- If P1 died without detaching XDP:
  ```sh
  sudo ip link set dev <iface> xdp off
  ```
