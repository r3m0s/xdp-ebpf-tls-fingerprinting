1. Attach basic eBPF module (Socket filters, XDP, Traffic Control)
2. Implement partial or full JA3/4 (or simple TLS handshake fingerprinting) hashing inside eBPF module
3. Share updateable JA4 map from user-space with eBPF module
4. Block incoming traffic based on JA3/4 fingerprint hash matches (e.g. test with browser traffic hash)
