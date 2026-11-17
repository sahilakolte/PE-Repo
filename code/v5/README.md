# NF chaining with a monitor

Packets go through a **chain of NFs** (`nf1 → nf2 → …`). A privileged **monitor** sets the chain up and wires it together. Each NF knows only its own input and output. It never knows which NF comes before or after it.


```
                       HTTP response from server (TCP port 80/443)
                                     │
       NIC ── XDP: port == 80/443? ──┤ no ──► normal kernel stack
                                     │ yes
                                     ▼
 ┌──────────── monitor (root) ────────────┐
 │ AF_XDP RX ring on the shared UMEM      │
 └──┬──────────────────────────────────▲──┘
    │ p0                               │ pN
    ▼                                  │
  ┌─────┐  p1   ┌─────┐  p2        ┌───────┐
  │ NF1 │ ────► │ NF2 │ ────► ...  │  NFN  │
  └─────┘       └─────┘            └───────┘
   

 All processes mmap the same memfd UMEM. Only 16-byte descriptors {offset,len,flags} travel through the pipes.
```

## Files

| File | Purpose |
|---|---|
| `monitor.c` | Reads the config, creates the UMEM (memfd) and one pipe per hop, registers NFs, attaches XDP, and runs RX → chain → sink. |
| `nf_lib.h` | NF runtime: connects to the monitor, maps the UMEM, and runs the read → handler → write loop. |
| `nf1.c`, `nf2.c`, `nf3.c` | Example NFs. Each one prints the packet and passes it on. |
| `chain.conf` | Interface, port filter, sink, and NF order. |
| `xdp_kern.c` | Steers only IPv4 TCP packets with the configured **source port** into AF_XDP. All other packets get `XDP_PASS`. |
| `xdp_common.h` | Descriptor format, pipe and fd-passing helpers, packet printing. |
| `run_nfs.sh` | Starts every NF listed in `chain.conf`. |

## Build and run

You can start these in any order:

```sh
# Terminal 1 (root)
make run-monitor                     # uses chain.conf (iface wlp0s20f3)
make run-monitor RX_IFACE=eth0       # override the interface

# Terminal 2 (no root): starts nf1 and nf2
make run-nfs                         # or run ./nf1 and ./nf2 in separate terminals

# Terminal 3
curl -4 http://example.com           # plain HTTP on port 80, IPv4
```

Expected output: the same packet appears in every stage. The `off=` value is identical everywhere, while `va=` differs per process.

```
[RX  ] off=0x00000100 va=0x7f4241a00100 TCP 93.184.215.14:80 -> 192.168.1.23:51234 [AP] payload=42 "HTTP/1.1 200 OK"
[NF1 ] off=0x00000100 va=0x7f055a000100 TCP 93.184.215.14:80 -> 192.168.1.23:51234 [AP] payload=42 "HTTP/1.1 200 OK"
[NF2 ] off=0x00000100 va=0x7f9818a00100 TCP 93.184.215.14:80 -> 192.168.1.23:51234 [AP] payload=42 "HTTP/1.1 200 OK"
[OUT ] off=0x00000100 ...   (handed to the kernel; curl receives it)
```

## Adding an NF (e.g. nf3)

1. Write `nf3.c`. Copy `nf1.c` and change the name; there is already one in this folder.
2. Add it to the chain in `chain.conf`: `chain nf1 nf2 nf3`.
3. Run `make` (it builds every `nf*.c` automatically) and restart.

You don't change nf1, nf2 or the monitor code. You can also reorder the chain (`chain nf2 nf1`) without recompiling anything.

An NF is just a handler with no return value. Every packet always moves on to the next stage:

```c
#include "nf_lib.h"

static void handle(struct nf_pkt *p)      // p->data, p->len, p->off
{
    print_packet_info(p->data, p->off, p->len, "NF3");
}

int main(void) { return nf_run("nf3", handle); }
```

## Lifecycle

- **Registration.** An NF started before the monitor keeps retrying the connection. The monitor refuses names that are not in the chain or that are already registered. XDP is attached only after **all** NFs have registered.
- **Shutdown.** On Ctrl+C the monitor closes `p0`. NF1 sees EOF and closes its output, then NF2 sees EOF, and so on down the chain. If any NF dies, its neighbours see EOF or EPIPE, and the whole chain shuts down and detaches XDP.
