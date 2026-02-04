CC=gcc
BPFC=clang

CFLAGS=-O2 -Wall
BPFFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86 -I..

all: hello.bpf.o loader

hello.bpf.o: simple_execve.c
	$(BPFC) $(BPFFLAGS) -c -o $@ $^

loader: loader.c
	$(CC) $(CFLAGS) -o $@ $^ -lbpf

clean:

mrproper:
	rm -f *.bpf.o loader

