Some explanation for the current code:

* **Kernel eBPF Attachment (`xdp_kern.c`):** Loads an eBPF program into xdp to intercept packets as soon as they reach the NIC.


* **Socket Registration Map:** Maintains a map (`xsks_map`) that pairs receive (RX) queue IDs with AF_XDP socket file descriptors.


* **Packet Redirection:** For each incoming packet, the eBPF code checks `xsks_map`. If an AF_XDP socket is mapped to the current queue ID, it executes `bpf_redirect_map()` to route the packet payload straight to userspace. Otherwise, it returns `XDP_PASS` to let the packet go through the standard Linux network stack.


* **Shared Memory (UMEM) Setup (`xdp_user.c`):** Userspace allocates a chunk of memory (`mmap`) into fixed-size frames and registers it as a `UMEM`. This creates a shared buffer space between the kernel and userspace for direct packet transfers.


* **Socket Creation & Configuration:** Opens an AF_XDP socket bound to queue 0, updates `xsks_map` with its file descriptor, and populates the **Fill Queue** with empty UMEM frame addresses so the kernel knows where to place incoming packet data.


* **Polling & Packet Processing:** Continually checks the socket's **RX Ring** in batches. When packets arrive, it uses `xsk_umem__get_data()` to inspect the raw packet headers and prints source and destination IP addresses.


* **Frame Recycling & Cleanup:** Once processed, userspace submits the used frame addresses back into the Fill Queue for the kernel to reuse. Upon exiting (via Ctrl+C), it detaches the eBPF program and cleans up socket resources.