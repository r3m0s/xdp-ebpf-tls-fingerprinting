1. Attach basic eBPF module (Socket filters, XDP, Traffic Control)
2. Implement partial or full JA3/4 (or simple TLS handshake fingerprinting) hashing inside eBPF module
3. Share updateable JA4 map from user-space with eBPF module
4. Block incoming traffic based on partial JA3/4 fingerprint (e.g. restricted to HTTP/TLS fingerprinting) hash matches
5. Test with browser traffic hash

Links:

https://github.com/FoxIO-LLC/ja4

https://github.com/salesforce/ja3

https://sslbl.abuse.ch/ja3-fingerprints/

https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e
