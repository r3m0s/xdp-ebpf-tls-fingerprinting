```tex
65 42 50 46  58 44 50  49 6E 73 70 65 63 74 69 6F 6E 

     ___ ___ ___  __  _____  ___   ___                      _   _          
 ___| _ ) _ \ __| \ \/ /   \| _ \ |_ _|_ _  ____ __  ___ __| |_(_)___ _ _  
/ -_) _ \  _/ _|   >  <| |) |  _/  | || ' \(_-< '_ \/ -_) _|  _| / _ \ ' \ 
\___|___/_| |_|   /_/\_\___/|_|   |___|_||_/__/ .__/\___\__|\__|_\___/_||_|
                                              |_|            
```

# XDP eBPF Module for TLS Client Fingerprinting
This project is an experimental proof-of-concept to inspect inbound network traffic and block a specific TLS client using fingerprinting mechanisms at high-speed directly within an Express Data Path (XDP) Extended Berkeley Packet Filter (eBPF) module running in the Linux kernel, attached to the network driver's XDP-hook. Development took place during the advanced system security (ADSS) lecture at the Lucerne University of Applied Sciences and Arts (HSLU), further extensions and restrictions might be introduced at a future point in time.

**Initial Group Concept Discussion:**

1. Attach basic eBPF module (Socket filters, XDP, Traffic Control)
2. Implement partial or full JA3/4 (or simple TLS handshake fingerprinting) hashing inside eBPF module
3. Share updateable JA4 map from user-space with eBPF module
4. Block incoming traffic based on partial JA3/4 fingerprint (e.g. restricted to HTTP/TLS fingerprinting) hash matches
5. Test with browser traffic hash

**Useful Links:**

- Blog Post 1 on JA3 by Jon Althouse: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
- Blog Post 2 on JA3 by Jon Althouse: https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41/
- Original Repository by Jon Althouse, Jeff Atkinson, Josh Atkins: https://github.com/salesforce/ja3
- Modern JA4+ fingerprinting: https://github.com/FoxIO-LLC/ja4
- Database of malicious JA3 fingerprints by abuse.ch: https://sslbl.abuse.ch/ja3-fingerprints/
- Tigera XDP eBPF tutorial: https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/
- In-depth lab visualizations by Teodor Janez Podobnik: https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e
- Original TLS fingerprinting idea from Lee Brotherston: https://github.com/LeeBrotherston/tls-fingerprinting/tree/master/fingerprintls

# Usage Instructions
> [!WARNING]  
> Loading this kernel module could lock you out of your virtual machine. Use at your own risk.

```sh
# build loader and XDP eBPF module
make
# attach module to loopback interface
sudo ./xdp_ebpf_loader lo xdp_ebpf_module.bpf
# hook into module's kernel debug logs in separate terminal window
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Local Testing
Create a local public/private key pair and a certificate for the python webserver that will be running on `127.0.0.1` according to the descriptions in [Creating Certificates for the Python Server](#creating-certificates-for-the-python-server).

1. Load eBPF to lo (loopback) interface: `sudo ./xdp_ebpf_loader lo xdp_ebpf_module.bpf`
2. Start local python webserver: `sudo python3 tls_server.py`, or for client certificate logging: `sudo python3 tls_server_advanced.py`
3. Do `curl --insecure -v https://127.0.0.1:443`, insecure (no server certificat verification) and in verbose mode
4. Validate verbose logs in the user space loader and the kernel module's logs

Test with wget and python clients to get other fingerprints:

- `wget --no-check-certificate -v https://127.0.0.1:443`
- `python3 -c "import requests; print(requests.get('https://127.0.0.1').text)"`

You could also try a request with a client certificate `curl --insecure -v --key key.pem --cert cert.pem https://127.0.0.1`.

## Remote Testing
1. Load eBPF to ens3/eth0 interface: `sudo ./xdp_ebpf_loader ens3 xdp_ebpf_module.bpf`
2. Do `curl https://google.com`

## Creating Certificates for the Python Server
One line command that includes subject alternative names (SAN) to make certificate work with `wget` client:

```sh
openssl req -x509 -out cert.pem -keyout key.pem -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

Manual creation (will not work with `wget` due to missing SANs):

```sh
# Create private key
openssl genrsa -out key.pem 2048
# Create a self‑signed certificate valid for 365 days
openssl req -new -x509 -key key.pem -out cert.pem -days 365
Country Name (2 letter code) [AU]:CH
State or Province Name (full name) [Some-State]:Lucerne
Locality Name (eg, city) []:Lucerne 
Organization Name (eg, company) [Internet Widgits Pty Ltd]:HSLU 
Organizational Unit Name (eg, section) []:Security
Common Name (e.g. server FQDN or YOUR name) []:example.com
Email Address []:test@example.com
```

## Further Useful Commands
Attaching to interface manually without loader:

```sh
sudo ip link set dev lo xdp obj minimal_xdp.bpf sec xdp
ip link show lo
```

Unload XDP program manually from interface and restart network daemon/service:

```sh
sudo ip link set dev ens3 xdpgeneric off
sudo ip link set dev ens3 xdp off
sudo systemctl restart systemd-networkd
```

## Comparing CURL JA3 Fingerprint with External Tools
```sh
curl --insecure https://tls.browserleaks.com/json
THEIRS: 771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-10-11-13-16-21-22-23-43-45-49-51,29-23-30-25-24-256-257-258-259-260,0-1-2
OURS: 771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21
```

# Extra Tools
The folder "Tools" contains two extra C-programs which generate TLS fingerprints using the OpenSSL "EVP" API.

## Build Tools
The two programs for JA3 and JA4 hash calculation can be built using make.

```sh
make
```

## Raw Data to JA3 Hash
The `string2ja3` file produces a 32-character JA3 jhash of the raw TLS handshake string using MD5.
### Sample Output
```sh
# Usage: ./string2ja3 <ja3_raw_string>
# Example:
./string2ja3 "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-16-35-0-23-65281-5-13-51-11-65037-43-27-10-18-17613,4588-29-23-24,0"

JA3 hash: df37f2fd952c0b0b586cf0d9d850c8b2
```

## Raw Data to JA4 Hash
The `string2ja4` file produces a JA4 fingerprint using SHA-256, but keeping the protocol prefix in plaintext.
### Sample Output
```sh
# Usage: ./string2ja4 <ja4_raw_string>
# Format: prefix_ciphers_extensions_sigalgs
# Example:
./string2ja4 "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601"

JA4 hash: t13d1516h2_8daaf6152771_d8a2da3f94cd
```

# Known Errors and Fixes
## ASM Types File not Found Error
Fixing error when compiling minimal XDP packet capturing tool. Error message when compiling with `make`:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I.. -c -o minimal_xdp.bpf minimal_xdp.c
In file included from minimal_xdp.c:9:
In file included from /usr/include/linux/ip.h:20:
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
```

Solution (see: https://stackoverflow.com/questions/77454504/asm-types-h-error-during-compilation-of-ebpf-code):

```sh
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

## Cleanup XDP Module Manually
- `sudo ip link set dev lo xdpgeneric off`
- `sudo ip link set dev ens3 xdpgeneric off`
