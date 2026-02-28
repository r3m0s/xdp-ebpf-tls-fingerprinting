// Copyright (C) 2026

// perror()
#include <errno.h>
// if_nametoindex
#include <net/if.h>
// for XDP_FLAGS constants
#include <linux/if_link.h>
// I/O
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// libbpf functions (bpf_object__open_file)
#include <bpf/libbpf.h>
// bpf_map_update_elem
#include <bpf/bpf.h>
// signal handling
#include <signal.h>
// openssl MD5 functionality
#include <openssl/md5.h>

#define MAX_TLS_EXTENSIONS 16
#define MAX_TLS_CIPHER_SUITES 32

#define BLOCKED_JA3_HASH "e95534fc5bdd63a753b688a2fcb20b47"

// event struct from eBPF kernel module
struct fingerprint_event {
    uint16_t version;
    uint16_t ciphers[MAX_TLS_CIPHER_SUITES];
    uint16_t ciphers_count;
    uint16_t extensions[MAX_TLS_EXTENSIONS];
    uint8_t extensions_count;
    uint8_t has_elliptic_curves;
    uint8_t has_formats;
    uint8_t sni_present;
    uint8_t alpn[4];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

// obj struct for operating on bpf object
static struct bpf_object *obj;

static int decisions_fd = -1;

// atomic singal-safe flag for interrupt handling
static volatile sig_atomic_t stop = 0;

// fingerprint event counter
static unsigned long fingerprint_events_counter = 0;

// sets global atomic stop flag to 1 when an interrupt occurs (Ctrl-C)
static void handle_sigint(int sig) { stop = 1; }

// computes md5 hash on provided ja3-formatted string and returns hash in output buffer
int ja3_hash(const char *ja3_fmt_string, char *md5) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    
    // compute MD5 hash
    MD5((unsigned char*)ja3_fmt_string, strlen(ja3_fmt_string), digest);
    
    // convert digest to hex string (32 characters => 16 bytes => 16*2 hex digits)
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5 + (i * 2), "%02x", digest[i]);
    }
    // zero-terminate MD5 hash output character array
    md5[32] = '\0';
    return 0;
}

// extracts TLS fingerprint data from kernel event and prints information
static void handle_event(void *ctx, int cpu, void *data, uint32_t size) {
    fingerprint_events_counter++;
    printf("> Fingerprint Event %lu:\n", fingerprint_events_counter);

    // parse raw bytes from event into user space struct for easier access
    struct fingerprint_event *event = data;
    // 33 bytes character array for JA3 MD5 hash of 32 bytes and zero-termination
    char ja3[33] = {0};
    // format string buffer for TLS fingerprint
    // JA3 format: TLSVersion,Ciphers,ExtensionTypes,EllipticCurves,EllipticCurvePointFormats
    char fmt_tls_fingerprint[512] = {0};
    int byte_offset = 0;
    
    // insert TLSVersion at offset 0, constraining max writeable bytes to buffer size minus written offset
    byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, "%u", event->version);

    // insert ciphers separated with comma and internally concatenated with dashes
    if (event->ciphers_count > 0) {
        byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, ",");

        for (int i = 0; i < event->ciphers_count; i++) {
            // insert dashes only after first cipher
            if (i > 0) byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, "-");
            // insert cipher always
            byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, "%u", event->ciphers[i]);
        }
    }

    // insert extension types separated with comma and internally concatenated with dashes
    if (event->extensions_count > 0) {
        byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, ",");
        for (int i = 0; i < event->extensions_count; i++) {
            if (i > 0) byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, "-");
            byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, "%u", event->extensions[i]);
        }
    }

    // insert padding 0 for missing EllipticCurves and EllipticCurvePointFormats
    byte_offset += snprintf(fmt_tls_fingerprint + byte_offset, sizeof(fmt_tls_fingerprint) - byte_offset, ",0,0");

    // hash JA3 string using MD5 from openssl (hash is returned in ja3 buffer)
    ja3_hash(fmt_tls_fingerprint, ja3);

    // hash to pass decision for specific fingerprint back to kernel space
    uint32_t session_hash = 0xEB9FAD55 ^ event->src_ip ^ event->dst_ip ^ event->src_port ^ event->dst_port;

    printf("Userspace hashmap session hash: %x\n\n", session_hash);

    // decide on whether hash is malicious or not
    uint8_t decision = strncmp(ja3, BLOCKED_JA3_HASH, 32) == 0 ? 0 : 1;

    // send decision back to kernel space
    bpf_map_update_elem(decisions_fd, &session_hash, &decision, BPF_ANY);

    printf("TLS client fingerprint:\n%s\n\n", fmt_tls_fingerprint);
    printf("JA3 MD5 hash:\n%s\n\n", ja3);
    if (decision == 0) printf("WARNING: MALICIOUS TLS CLIENT PACKET\n\n");
}

int main(int argc, char **argv) {
    // bpf program for operating on obtained handles
    struct bpf_program *prog;

    // bpf map and buffer to receive events
    struct bpf_map *map;
    struct perf_buffer *pb;

    int err;

    // open and load the eBPF object file (ELF) for parsing
    // parses ELF sections, reads metadata, but does not load anything into the kernel yet
    obj = bpf_object__open_file(argv[2], NULL);
    if (!obj) {
        perror("Error while opening eBPF object file.");
    }

    // JIT-compilation and loads eBPF bytecode into kernel
    err = bpf_object__load(obj);
    if (err) {
        perror("Error while compiling and loading eBPF bytecode into kernel.");
    }
    
    // find XDP program by name (name of the C function in the eBPF code)
    prog = bpf_object__find_program_by_name(obj, "minimal_xdp");
    if (!prog) {
        perror("Error while finding eBPF program by name.");
    }

    // obtain kernel file descriptor for attachment
    int prog_fd = bpf_program__fd(prog);

    // convert interface name (eth0, ens3, lo) to numeric index and attach XDP program to the interface (post-driver/pre network-stack)
    int ifidx = if_nametoindex(argv[1]);
    err = bpf_xdp_attach(ifidx, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err < 0) {
        perror("Error while attaching XDP program to interface.");
    }

    printf("View output with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    // obtain file descriptor to decisions hash map in kernel
    decisions_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "decisions"));

    // find file descriptor handle towards the buffer map to listen for kernel-events
    map = bpf_object__find_map_by_name(obj, "fingerprint_events");
    int map_fd = bpf_map__fd(map);

    // receive and handle events from the kernel, then print them formatted
    pb = perf_buffer__new(map_fd, 64, handle_event, NULL, NULL, NULL);

    // listen for Ctrl-C and handle signal
    signal(SIGINT, handle_sigint);

    printf("Waiting for events from eBPF/XDP module... \nPress Ctrl-C to detach and exit...\n\n");
    while (!stop) {
        // poll for events with 100ms timeouts until interrupt signal is received and sets stop to 1
        perf_buffer__poll(pb, 100);
    }
    
    // cleanup, releases kernel resources (unload program and maps)
    bpf_object__close(obj);

    // detatch XDP program from interface
    bpf_xdp_detach(ifidx, XDP_FLAGS_SKB_MODE, NULL);
    
    return EXIT_SUCCESS;
}