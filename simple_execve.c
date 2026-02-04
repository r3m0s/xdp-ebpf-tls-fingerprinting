#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_execve")
int hello(void *ctx) {
    bpf_printk("eBPF: tracing execve!");
    return 0;
}
