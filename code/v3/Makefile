CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g -Wall

# xdp_user1 is the only program that still opens a real AF_XDP socket and
# loads a BPF program. -lrt is for shm_open/shm_unlink (POSIX shared
# memory used for the shared UMEM and the redirect rings in
# xdp_common.h) -- a harmless no-op on glibc >= 2.34, where these live
# directly in libc, but needed on older glibc. -lpthread is for the
# ksoftirqd_thread in xdp_user1.
LIBS_XSK  := -lbpf -lxdp -lrt -lpthread
LIBS_USER2 := -lrt

RX_IFACE ?= wlp0s20f3

all: xdp_kern.o xdp_user1 xdp_user2

# The kernel-side eBPF program, compiled to BPF bytecode. Only xdp_user1
# loads this now -- xdp_user2 no longer touches AF_XDP/XDP at all.
xdp_kern.o: xdp_kern.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# Program 1: the only real AF_XDP consumer. Receives on the NIC and
# redirects packet descriptors to program2 via shared memory (see
# xdp_common.h) instead of transmitting them out a veth.
xdp_user1: xdp_user1.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_XSK)

# Program 2: a plain shared-memory consumer. No AF_XDP socket, no NIC,
# no XDP program, no root required.
xdp_user2: xdp_user2.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_USER2)

# Run program1 (needs root: real AF_XDP socket + loading a BPF program).
run1: xdp_kern.o xdp_user1
	sudo ./xdp_user1 $(RX_IFACE)

# Run program2 -- no root needed. Start in a second terminal, before or
# after run1; it just waits for redirected packets to show up in shared
# memory.
run2: xdp_user2
	./xdp_user2

clean:
	rm -f xdp_kern.o xdp_user1 xdp_user2

# Both processes unlink their shared-memory objects on clean exit, but a
# crash or `kill -9` can leave them behind. This removes them by hand.
clean-shm:
	-rm -f /dev/shm/xdp_shared_umem /dev/shm/xdp_redirect_shm

.PHONY: all run1 run2 clean clean-shm
