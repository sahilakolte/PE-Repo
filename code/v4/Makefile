CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g -Wall

# -lrt: shm_open/shm_unlink for the shared UMEM (no-op on glibc >= 2.34)
LIBS_XSK   := -lbpf -lxdp -lrt -lpthread
LIBS_USER2 := -lrt

RX_IFACE ?= wlp0s20f3

all: xdp_kern.o xdp_user1 xdp_user2

xdp_kern.o: xdp_kern.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# Program 1: real AF_XDP receiver; sends UMEM offsets to program 2
# through the named pipe /tmp/xdp_p1_to_p2.
xdp_user1: xdp_user1.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_XSK)

# Program 2: reads offsets from the pipe, reads packets in place from the
# shared UMEM, returns offsets via /tmp/xdp_p2_to_p1. No root needed.
xdp_user2: xdp_user2.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_USER2)

# Run each in its own terminal, in either order.
run1: xdp_kern.o xdp_user1
	sudo ./xdp_user1 $(RX_IFACE)

run2: xdp_user2
	./xdp_user2

clean:
	rm -f xdp_kern.o xdp_user1 xdp_user2

# Leftovers after a crash / kill -9 (FIFOs are harmless to leave around).
clean-ipc:
	-sudo rm -f /dev/shm/xdp_shared_umem /tmp/xdp_p1_to_p2 /tmp/xdp_p2_to_p1

.PHONY: all run1 run2 clean clean-ipc
