# AF_XDP Packet Redirection Experiments

Step-by-step experiments with **AF_XDP**, moving from a simple packet sniffer to zero-copy packet redirection between co-located network functions (NFs), inspired by **FLASH (SoCC '25)**. Each version is in `code/vN/` and has its own README with build and run details.

## Versions

| Version | Summary |
|---|---|
| [`v1`](code/v1) | **Single-process sniffer.** An eBPF program on the NIC's XDP hook redirects packets to one AF_XDP socket, and the userspace program prints source/destination IPs. Uses only the fill queue and RX ring. |
| [`v2`](code/v2) | **Two-process relay over veth.** `xdp_user1` receives from the NIC and re-transmits each frame out `veth1` (TX ring + completion queue). `xdp_user2` receives it on `veth2` with its own AF_XDP socket and UMEM. A packet hash in both logs confirms the same packet arrived. |
| [`v3`](code/v3) | **Shared-memory redirect with SPSC rings.** The veth wire is replaced by a shared UMEM (POSIX shm) and two lock-free SPSC rings that carry descriptors. A dedicated `ksoftirqd_thread` in `xdp_user1` handles RX and redirect. `xdp_user2` reads packets in place without a socket or root. |
| [`v4`](code/v4) | **Zero-copy redirect over named pipes.** The SPSC rings are replaced by two FIFOs: P1 sends `{offset, len}` descriptors and P2 returns offsets for recycling. Both processes read the same physical bytes. Logs show identical offsets and different virtual addresses. Neither program busy-waits. |
| [`v5`](code/v5) | **NF chaining with a monitor.** A privileged monitor reads `chain.conf`, creates a memfd UMEM and one pipe per hop, and wires a configurable chain of NFs (`nf1 → nf2 → nf3`). XDP steers only TCP packets with a chosen source port into the chain. NFs are written against `nf_lib.h`, can be added or reordered from the config, and shut down cleanly when any stage exits. |

## Papers

The `papers/` folder holds the reference papers:

- `2025-flash.pdf`: FLASH (SoCC '25), the basis for the zero-copy redirect design in v3–v5
- `2026-toasty.pdf`
