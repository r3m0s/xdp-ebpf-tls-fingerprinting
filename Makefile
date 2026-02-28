CC=gcc
BPFC=clang

CFLAGS=-O2 -Wall
BPFFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86 -I..

all: xdp_ebpf_module.bpf xdp_ebpf_loader.o

xdp_ebpf_module.bpf: xdp_ebpf_module.c
	$(BPFC) $(BPFFLAGS) -c -o $@ $^

# requires openssl development package installation: sudo apt install libssl-dev
xdp_ebpf_loader.o: xdp_ebpf_loader.c
	$(CC) $(CFLAGS) -o $@ $^ -lbpf -lssl -lcrypto

clean:

mrproper:
	rm -f *.bpf *.o
