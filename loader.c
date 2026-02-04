#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    // open and load the BPF object
    // Parses the ELF object file, reads metadata, but doesn't load anything into the kernel yet. It:
    // - Parses ELF sections
    // - Reads BTF (BPF Type Format) info
    // - Identifies programs, maps, relocations
    // - Returns a handle to work with
    obj = bpf_object__open_file("hello.bpf.o", NULL);
    if (!obj) {
        perror("Error while opening BPF object file.");
    }

    // load eBPF bytecode into the kernel
    err = bpf_object__load(obj);
    if (err) {
        perror("Error while loading BPF object file.");
    }
    
    // program is loaded, but not attached yet
    // first, find the program by name (name of the C function in the eBPF code)
    prog = bpf_object__find_program_by_name(obj, "hello");
    if (!prog) {
        perror("Error while finding BPF program by name.");
    }
    
    // attach program
    // attaches based on SEC() annotation and attaches appropriately
    // SEC("kprobe/...") kprobe
    // SEC("tracepoint/...") tracepoint
    // SEC("xdp") network interface
    // ...
    link = bpf_program__attach(prog);
    if (!link) {
        perror("Error while attaching BPF program.");
    }

    printf("View output with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Press Ctrl-C to detach and exit...\n");
    
    // keep running until user presses <Enter>
    char c;
    scanf("%c", &c);
    
    // cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);
    
    return EXIT_SUCCESS;
}
