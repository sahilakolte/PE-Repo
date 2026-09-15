CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g -Wall
LIBS    := -lbpf -lxdp
IFACE 	:= wlp0s20f3

all: xdp_kern.o xdp_user

# The kernel-side eBPF program is compiled to BPF bytecode.
xdp_kern.o: xdp_kern.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# The userspace loader/receiver is a normal native binary.
xdp_user: xdp_user.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

run: all
	sudo ./xdp_user $(IFACE)

clean:
	rm -f xdp_kern.o xdp_user

.PHONY: all run clean
