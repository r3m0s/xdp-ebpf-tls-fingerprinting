// IMPORTANT: sizeof(tlshdr) cannot be used as offset as it adds a padding byte, resulting in offset 6 instead of hardcoded 5
// NOTE: __attribute__((packed)) modifier cannot be used in eBPF to disable padding between fields and avoid misalignment while parsing network packets
// IMPORTANT: XDP acts at layer 2; Therefore fragmented packets may occur due to XDP's truncation of packets, they would need to be reassembled before processing -> full reassembly needs TC or kernel patches.

// exported type definitions for running Linux kernel
#include "vmlinux.h"
// macros and wrapper functions for eBPF module development (maps, SEC, bpf_printk)
#include <bpf/bpf_helpers.h>

// limit number of TLS extensions and cipher suites
#define MAX_TLS_EXTENSIONS 16
#define MAX_TLS_CIPHER_SUITES 32

// struct for TLS record header (https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record)
struct tlshdr {
    uint8_t content_type;
    uint8_t major_version;
    uint8_t minor_version;
    uint16_t length;
};

// struct for additional header fields in TLS handshake record (https://en.wikipedia.org/wiki/Transport_Layer_Security#Handshake_protocol)
struct tlshds {
    uint8_t message_type;
    uint8_t length[3];
};

// struct to send fingerprint information to user space
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
};

// Linux performance counter (PCL) event arrays for line-rate TLS fingerprinting and hashing in user-space (placed in .maps ELF section)
struct {
    // perf ring buffer event type for high-performance streaming to user-space
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    // perf events are indexed by CPU ID (network: 0)
    __uint(key_size, sizeof(uint32_t));
    // 32-bit file descriptor handle for buffer
    __uint(value_size, sizeof(uint32_t));
    // automatically set max CPU identifier index number to number of processor units (CPUs)
    __uint(max_entries, 0);
} fingerprint_events SEC(".maps");

// hash map for passing decisions from user space to kernel
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    // hashed event for reference
    __type(key, uint64_t);
    // value is 1 for pass and 0 for drop
    __type(value, uint8_t);
} decisions SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

// inlined custom network byte order conversion fuctions within eBPF module to limit function call overhead
static __always_inline uint16_t bpf_ntohs(uint16_t x) {
    return ((x >> 8) & 0xff) | ((x & 0xff) << 8);
}
static __always_inline uint32_t bpf_ntohl(uint32_t x) {
    return ((x >> 24) & 0xff) | ((x >> 8) & 0xff00) | ((x & 0xff00) << 8) | ((x & 0xff) << 24);
}

// attach eBPF module of type express data path (XDP) running in Linux kernel's network driver to process inbound packets
SEC("xdp")
int minimal_xdp(struct xdp_md *ctx) {
    // obtain packet start pointer: long is 4 bytes on 32-bit and 8 bytes on 64-bit systems, which correlates with void pointer size
    void *data = (void *)(long)ctx->data;
    // obtain packet end boundary pointer
    void *data_end = (void *)(long)ctx->data_end;

    // initial bytes are parsed into the ethernet header structure
    struct ethhdr *eth = data;
    // ignore malformed packets that do not contain a full ethernet header structure (+ sizeof(struct ethhdr))
    if ((void *)eth + sizeof(struct ethhdr) > data_end) {
        bpf_printk("Ethernet header exceeds packet\n");
        return XDP_DROP;
    }

    // IP header follows directly after ethernet header, parse it into iphdr structure and do identical bounds-check
    struct iphdr *iph = (void *)eth + sizeof(struct ethhdr);
    if ((void *)iph + sizeof(struct iphdr) > data_end) {
        bpf_printk("IP header exceeds packet\n");
        return XDP_DROP;
    }

    // internet header length at 4-bit offset specifies number of 32-bit words in the IP header (min 5, max 15). Size is dynamic due to optional "options" field at 160-bit offset (multiplier 32/8 converts amount of words to # bytes)
    uint32_t internet_header_length = iph->ihl * (32 / 8);
    // parse 16-bit total length field (total packet length, including data payload) at offset 16 and transform from big-endian to host byte order (see: https://en.wikipedia.org/wiki/IPv4#Header)
    uint16_t total_packet_length = bpf_ntohs(iph->tot_len);
    // ignore malformed packets that are declared to be longer than the received packet or are too short for an IP header
    if (total_packet_length < sizeof(struct iphdr)) {
        bpf_printk("Packet length is too short for full IP header\n");
        return XDP_DROP;
    }

    // print client IP
    // bpf_printk("SOURCE_IP: %pI4\n", &iph->saddr);

    // check protocol header field at 72-bit offset; size is 8 bits = 1 byte (2 hex digits), therefore network to host byte order transformation not needed (no endianness)
    if (iph->protocol == IPPROTO_TCP) {
        // 0x06 (= 6): TCP

        // initialize empty struct for passing event with data to user space
        struct fingerprint_event ev = {};

        // parse TCP header after IP header (https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)
        struct tcphdr *tcp = (void *)iph + internet_header_length;
        // side-note: sizeof(struct tcphdr) is the same as sizeof(*tcp) which would be expanded to the first during compilation
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
            bpf_printk("TCP header exceeds packet\n");
            return XDP_DROP;
        }

        // only block TLS/HTTPS traffic on destination port 443, let non-TLS clients on other ports pass for now
        if (bpf_ntohs(tcp->dest) != 443) {
            // bpf_printk("Passing non-HTTPS traffic on alternate port\n");
            return XDP_PASS;
        }
        bpf_printk("Appyling fingerprinting for HTTPS/TLS packet detected on port 443\n");

        // read 4-byte data offset value at 96-bit offset in TCP header which specifies the length (min 5, max 15) of the header in 32-bit (4 bytes) words
        uint8_t tcp_data_offset = tcp->doff * (32 / 8);

        // calculate actual data payload length by subtractig TCP payload start offset from packet length (= difference towards end)
        void *tcp_payload_start = (void *)tcp + tcp_data_offset;
        uint32_t data_payload_length = (void *)data_end - tcp_payload_start;

        // obtain pointer to start of TCP data payload (here TLS) by skipping to it with the data offset
        void *tls_header_start = (void *)tcp + tcp_data_offset;
        uint8_t* tls_header_bytewise = (uint8_t*)tls_header_start;
        struct tlshdr data_payload;
        
        // copy values manually into struct to avoid misalignment issues due to struct inserting paddings
        data_payload.content_type   = (uint8_t)tls_header_bytewise[0];
        data_payload.major_version  = (uint8_t)tls_header_bytewise[1];
        data_payload.minor_version  = (uint8_t)tls_header_bytewise[2];
        data_payload.length         = ((uint8_t)tls_header_bytewise[3] << 8) | (uint8_t)tls_header_bytewise[4];

        // let TCP handshake pass
        if (data_payload_length == 0) {
            bpf_printk("TCP handshake message received (SYN/ACK/FIN)\n");
            // let TCP SYN/ACK/FIN through which contain no inner payload and have a length of 0 towards packet end
            return XDP_PASS;
        }

        // ignore malformed TLS headers that are too short for required header fields
        if (data_payload_length < 5) {
            bpf_printk("TLS header too short and not valid\n");
            return XDP_DROP;
        }

        // ignore malformed TLS headers that exceed packet length
        if ((void *)tls_header_start + 5 > data_end) {
            bpf_printk("TLS header exceeds packet\n");
            return XDP_DROP;
        }

        // let non-handshake requests pass for now (0x16 = 22) to only read data payload that is in the process of setting up the TLS session and start blocking on session begin
        if (data_payload.content_type != 0x16) {
            // bpf_printk("TLS payload was not a handshake\n");
            return XDP_PASS;
        }

        // ignore malformed TLS headers that do not contain required handshake fields
        if ((void *)tls_header_start + 5 + 4 > data_end) {
            bpf_printk("TLS handshake header incomplete\n");
            return XDP_DROP;
        }

        // parse TLS handshake fields "message type" and "handshake message data length" starting at 5-bytes offset (https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record)
        struct tlshds *tls_handshake = (void *)tls_header_start + 5;
        // ignore malformed TLS handshake headers (size: 4 bytes) that exceed packet
        if ((void *)tls_handshake + 4 > data_end) {
            bpf_printk("TLS handshake header exceeds packet\n");
            return XDP_DROP;
        }

        // read TLS version from initial TLS header (legacy)
        ev.version = (data_payload.major_version << 8) | data_payload.minor_version;
        // (https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record)
        if (ev.version == 0x0300) {
            bpf_printk("SSL 3.0 DETECTED (legacy)\n");
        } else if (ev.version == 0x0301) {
            bpf_printk("TLS 1.0 DETECTED (legacy)\n");
        } else if (ev.version == 0x0302) {
            bpf_printk("TLS 1.1 DETECTED (legacy)\n");
        } else if (ev.version == 0x0303) {
            bpf_printk("TLS 1.2 DETECTED (legacy)\n");
        } else if (ev.version == 0x0304) {
            bpf_printk("TLS 1.3 DETECTED (legacy)\n");
        } else {
            bpf_printk("TLS %04x DETECTED (legacy)\n", ev.version);
        }

        // look for ClientHello handshake messages as they contain information for fingerprinting
        if (tls_handshake->message_type == 0x01) {
            // 3 byte "Handshake Message Data Length" field in TLS handshake header at offset 48 must be manually tranformed to host byte order
            uint32_t handshake_length = ((uint32_t)tls_handshake->length[0] << 16) | ((uint32_t)tls_handshake->length[1] << 8) | (uint32_t)tls_handshake->length[2];

            // parse client hello message directly after TLS handshake header
            uint8_t *client_hello_message = (uint8_t *)tls_handshake + sizeof(struct tlshds);
            // calculates bytes remaining in the TLS client hello message
            uint32_t available_bytes = (uint32_t)((void *)data_end - (void *)client_hello_message);
            // check whether handshake fits into TLS client hello message
            if (handshake_length > available_bytes) {
                handshake_length = available_bytes;
            }
            // ignore malformed ClientHello messages that exceed packet length
            if ((void *)client_hello_message + handshake_length > data_end) {
                bpf_printk("TLS ClientHello exceeds packet\n");
                return XDP_DROP;
            }

            // iterate over TLS handshake message fields (https://www.researchgate.net/publication/362029100/figure/fig2/AS:11431281092879652@1667016970475/a-ClientHello-and-b-ServerHello-message-structure.png)
            if ((void *)client_hello_message + 2 > data_end) {
                bpf_printk("ClientHello version exceeds packet\n");
                return XDP_DROP;
            }
            // read TLS version from message version field inside TLS ClientHello handshake header (newer and more precise field for TLS version) at offset 0 to 1 (first 2 bytes)
            ev.version = ((uint16_t)client_hello_message[0] << 8) | client_hello_message[1];
            if (ev.version == 0x0300) {
                bpf_printk("SSL 3.0 DETECTED (precise)\n");
            } else if (ev.version == 0x0301) {
                bpf_printk("TLS 1.0 DETECTED (precise)\n");
            } else if (ev.version == 0x0302) {
                bpf_printk("TLS 1.1 DETECTED (precise)\n");
            } else if (ev.version == 0x0303) {
                bpf_printk("TLS 1.2 DETECTED (precise)\n");
            } else if (ev.version == 0x0304) {
                bpf_printk("TLS 1.3 DETECTED (precise)\n");
            } else {
                bpf_printk("TLS %04x DETECTED (precise)\n", ev.version);
            }

            // SESSION ID
            // ignore malformed TLS messages that are too short for session ID length field
            if ((void *)client_hello_message + 35 > data_end) {
                bpf_printk("ClientHello session id length field exceeds packet\n");
                return XDP_DROP;
            }
            // parse session ID length at byte-offset 34
            uint8_t session_id_length = client_hello_message[34];
            // create upper bound of 32 bytes for session_id_length
            if (session_id_length > 32) {
                bpf_printk("Session ID field is too long\n");
                return XDP_DROP;
            }

            // CIPHER SUITES
            // calculate dynamic offset for cipher suites length field
            uint32_t cipher_suites_offset = 35 + (uint32_t)session_id_length;
            // ignore malformed TLS messages that are too short for cipher suites length field (2 bytes)
            if (cipher_suites_offset + 2 > handshake_length) {
                bpf_printk("ClientHello cipher suites length field exceeds handshake message length\n");
                return XDP_DROP;
            }
            // ignore malformed TLS messages which's cipher suites length field exceeds the packet length
            if ((void *)client_hello_message + cipher_suites_offset + 2 > data_end) {
                bpf_printk("ClientHello cipher suites length exceeds packet\n");
                return XDP_DROP;
            }

            // parse cipher suites length field at byte-offsets SID +35/+36, obtain a byte pointer for byte-wise sequential reading of 2 bytes
            uint8_t *cipher_suites_length_pointer = client_hello_message + cipher_suites_offset;
            // access pointer with absolute offsets 0 and 1, shifting to accomodate big-endian network byte-stream an transform to little-endian host byte order
            uint16_t cipher_suites_length = ((uint16_t)cipher_suites_length_pointer[0] << 8) | cipher_suites_length_pointer[1];
            // check if cipher suites length is even (2 bytes per cipher suite) and create a minimum bounds check (must have at least one cipher suite)
            if (cipher_suites_length % 2 != 0 || cipher_suites_length == 0) {
                bpf_printk("Cipher suites length is not even or 0\n");
                return XDP_DROP;
            }
            if ((uint32_t)session_id_length + 37 + cipher_suites_length > handshake_length) {
                bpf_printk("ClientHello cipher suites exceed handshake message length\n");
                return XDP_DROP;
            }
            if ((void *)client_hello_message + (uint32_t)session_id_length + 37 > data_end) {
                bpf_printk("ClientHello cipher suites exceed packet\n");
                return XDP_DROP;
            }

            // obtain pointer to start of cipher suites
            uint8_t *cipher_suites = client_hello_message + (uint32_t)session_id_length + 37;
            // create upper bounds for cipher suites (max 512 bytes)
            if (cipher_suites_length > 512) {
                bpf_printk("Too many cipher suites\n");
                return XDP_DROP;
            }
            if ((void *)cipher_suites + cipher_suites_length > data_end) {
                bpf_printk("ClientHello cipher suites exceed packet\n");
                return XDP_DROP;
            }

            uint16_t num_cipher_suites = cipher_suites_length / 2;
            // limit number of ciphers to 32 for fixed buffer
            ev.ciphers_count = num_cipher_suites;
            if (ev.ciphers_count > MAX_TLS_CIPHER_SUITES) ev.ciphers_count = MAX_TLS_CIPHER_SUITES;

            // iterate over cipher suites (2 bytes at a time)
            uint16_t i;
            for (i = 0; i < MAX_TLS_CIPHER_SUITES; i++) {
                // break if dynamic access to cipher suites exceed packet
                if ((void *)cipher_suites + (2 * i) + 2 > data_end) break;
                // transform bytes to host order and store them in uint16_t (2-byte) ciphers event array
                ev.ciphers[i] = ((uint16_t)cipher_suites[2 * i] << 8) | cipher_suites[2 * i + 1];
            }

            // print client-supported cipher suites
            if (ev.ciphers_count > 0) {
                bpf_printk("Supported TLS cipher suites: Count %u: %04x,%04x,%04x,%04x,%04x\n", ev.ciphers_count, ev.ciphers[0], ev.ciphers[1], ev.ciphers[2], ev.ciphers[3], ev.ciphers[4]);
            }

            // COMPRESSION METHODS
            uint8_t *after_ciphers = cipher_suites + cipher_suites_length;
            // compression methods length field (1 byte) must be inside handshake
            if ((void *)after_ciphers + 1 > (void *)client_hello_message + handshake_length) {
                bpf_printk("ClientHello compression methods length field exceeds handshake message length\n");
                return XDP_DROP;
            }
            // ignore malformed TLS messages that are too short for compression methods length field
            if ((void *)after_ciphers + 1 > data_end) {
                bpf_printk("ClientHello compression methods length field exceeds packet\n");
                return XDP_DROP;
            }
            // parse compression methods length at dynamic byte-offset
            uint8_t compression_methods_length = after_ciphers[0];
            // create upper bounds for cipher suites (max 32 bytes)
            if (compression_methods_length > 32) {
                bpf_printk("Compression methods field is too long\n");
                return XDP_DROP;
            }
            // compression methods are not of interest, no further parsing required, just considerd dynamic field lengths for subsequent access to extensions

            // ensure compression methods are inside handshake and packet
            uint8_t *after_compression = after_ciphers + 1 + compression_methods_length;
            if ((void *)after_compression > (void *)client_hello_message + handshake_length) {
                bpf_printk("ClientHello compression methods exceed handshake message length\n");
                return XDP_DROP;
            }
            if ((void *)after_compression > data_end) {
                bpf_printk("ClientHello compression methods exceed packet\n");
                return XDP_DROP;
            }

            // TLS EXTENSIONS
            // parse extension length field
            if ((void *)after_compression + 2 > (void *)client_hello_message + handshake_length) {
                bpf_printk("ClientHello extensions length field exceeds handshake message length\n");
                return XDP_DROP;
            }
            if ((void *)after_compression + 2 > data_end) {
                bpf_printk("ClientHello extensions length field exceeds packet\n");
                return XDP_DROP;
            }
            uint16_t extensions_length = ((uint16_t)after_compression[0] << 8) | after_compression[1];
            if (extensions_length > 512) {
                bpf_printk("Extensions too long\n");
                return XDP_DROP;
            }
            if ((void *)after_compression + 2 + extensions_length > (void *)client_hello_message + handshake_length) {
                bpf_printk("ClientHello extensions exceed handshake message length\n");
                return XDP_DROP;
            }
            if ((void *)after_compression + 2 + (uint32_t)extensions_length > data_end) {
                bpf_printk("ClientHello extensions exceed packet\n");
                return XDP_DROP;
            }

            // obtain pointer to start of extensions for subsequent absolute access
            uint8_t *extensions = after_compression + 2;
            // cast data_end void pointer to byte pointer for direct comparision with extensions byte pointer
            uint8_t *data_end_u8 = (uint8_t *)data_end;

            uint32_t byte_offset = 0;
            ev.extensions_count = 0;
            ev.has_elliptic_curves = 0;
            ev.has_formats = 0;

            while ((byte_offset + 4 <= extensions_length) && (ev.extensions_count < MAX_TLS_EXTENSIONS)) {
                // bound checks for verifier and store extensions + offset into pointer variable to avoid dynamic accesses in loop (eBPF will not load it otherwise)
                uint8_t *current_extension = extensions + byte_offset;
                if (current_extension + 4 > data_end_u8) break;

                uint16_t ext_type = ((uint16_t)current_extension[0] << 8) | current_extension[1];
                uint16_t ext_len = ((uint16_t)current_extension[2] << 8) | current_extension[3];

                if (ext_len > 512) break;

                // check that the full extension data fits within extensions_length and packet
                if (byte_offset + 4 + ext_len > extensions_length) break;
                if (current_extension + 4 + ext_len > data_end_u8) break;

                if (ext_type == 10) ev.has_elliptic_curves = 1;
                if (ext_type == 11) ev.has_formats = 1;

                // SNI extension present means domain-connection, otherwise IP-connection (https://en.wikipedia.org/wiki/Server_Name_Indication, https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record)
                if (ext_type == 0 && ext_len >= 3) {
                    if (current_extension + 9 <= data_end_u8) {
                        ev.sni_present = 1;
                    }
                }

                // ALPN allows to associate different certificates with each application protocol and choose the one used and presented inside the TLS handshake ClientHello/ServerHello (https://www.rfc-editor.org/rfc/rfc7301)
                

                // store extension types in packet order as received
                ev.extensions[ev.extensions_count] = ext_type;
                ev.extensions_count++;

                // proceed to next extension (length(4); extension(length))
                byte_offset += 4 + ext_len;
            }

            // print TLS extension types in order
            if (ev.extensions_count > 0) {
                bpf_printk("TLS extensions: Count %u: %04x,%04x,%04x,%04x,%04x\n", ev.extensions_count, ev.extensions[0], ev.extensions[1], ev.extensions[2], ev.extensions[3], ev.extensions[4]);
            }

            // submit event to user space loader for MD5 hashing: Use current CPU ID as map index (CPU that processes network packet) to spread and scale events accross individual ring buffers
            bpf_perf_event_output(ctx, &fingerprint_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

            uint64_t hash = 0x4D55;
            hash = ((hash << 5) + hash) ^ ev.version;
            for (int i = 0; i < 4 && i < ev.ciphers_count; i++)
                hash = ((hash << 5) + hash) ^ ev.ciphers[i];
            for (int i = 0; i < 4 && i < ev.extensions_count; i++)
                hash = ((hash << 5) + hash) ^ ev.extensions[i];

            bpf_printk("Kernelspace hashmap hash = %lx\n", hash);

            void *val = bpf_map_lookup_elem(&decisions, &hash);
            uint8_t decision = 255;
            if (val) decision = *((uint8_t *)val);

            if (decision == 0) {
                bpf_printk("MALICIOUS TLS CLIENT PACKETS DROPPED\n");
                return XDP_DROP;
            } else {
                bpf_printk("TLS CLIENT PACKETS PASSED\n");
                return XDP_PASS;
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        // 0x11 (= 17): UDP
        bpf_printk("PROTOCOL: UDP\n");

        // pass all UPD packets for now
        return XDP_PASS;
    }
    // insecure for now, pass everything else
    return XDP_PASS;
}