CLANG   ?= clang
CC      ?= gcc
CFLAGS  := -O2 -g -Wall

LIBS_MON := -lbpf -lxdp

CONF     ?= chain.conf
RX_IFACE ?=

# Every nf*.c in this folder is an NF. Adding nf4.c needs no Makefile edit.
NFS := $(patsubst %.c,%,$(wildcard nf*.c))

all: xdp_kern.o monitor $(NFS)

xdp_kern.o: xdp_kern.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

monitor: monitor.c xdp_common.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS_MON)

# NFs need no libbpf and no root.
$(NFS): %: %.c nf_lib.h xdp_common.h
	$(CC) $(CFLAGS) $< -o $@

# Terminal 1 (root)
run-monitor: xdp_kern.o monitor
	sudo ./monitor $(CONF) $(RX_IFACE)

# Terminal 2: starts every NF listed on the `chain` line of $(CONF)
run-nfs: $(NFS)
	./run_nfs.sh $(CONF)

clean:
	rm -f xdp_kern.o monitor $(NFS)

# After a crash / kill -9
clean-ipc:
	-sudo rm -f /tmp/flash_monitor.sock

.PHONY: all run-monitor run-nfs clean clean-ipc
