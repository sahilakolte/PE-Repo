CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g -Wall

# Both programs now open real AF_XDP sockets and load a BPF program.
LIBS_XSK := -lbpf -lxdp

RX_IFACE ?= wlp0s20f3
VETH1    ?= veth1
VETH2    ?= veth2

all: xdp_kern.o xdp_user1 xdp_user2

# The kernel-side eBPF program, compiled to BPF bytecode. Both userspace
# programs load this same object -- xdp_user1 attaches it to the real
# NIC, xdp_user2 attaches it to its veth interface.
xdp_kern.o: xdp_kern.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# Program 1: real AF_XDP RX on the NIC + real AF_XDP TX on a veth
# interface, sharing one umem. Prints [P1] and hands each frame off to
# program2 by transmitting it.
xdp_user1: xdp_user1.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_XSK)

# Program 2: independent real AF_XDP RX on the other end of the veth
# pair. Prints [P2].
xdp_user2: xdp_user2.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_XSK)

# Create the veth pair used as the "wire" between program1 and program2.
# Run once before run1/run2 (needs root).
veth-setup:
	sudo ip link add $(VETH1) type veth peer name $(VETH2)
	sudo ip link set $(VETH1) up
	sudo ip link set $(VETH2) up

veth-teardown:
	-sudo ip link del $(VETH1)

# Run program1 (needs root). Sniffs RX_IFACE, hands frames to VETH1.
run1: xdp_kern.o xdp_user1
	sudo ./xdp_user1 $(RX_IFACE) $(VETH1)

# Run program2 (needs root). Start in a second terminal, before or after
# run1 -- it just waits for packets to arrive on VETH2.
run2: xdp_kern.o xdp_user2
	sudo ./xdp_user2 $(VETH2)

clean:
	rm -f xdp_kern.o xdp_user1 xdp_user2

.PHONY: all veth-setup veth-teardown run1 run2 clean
