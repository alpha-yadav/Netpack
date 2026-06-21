# Network Packet Analyzer

A small, real-time, read-only packet capture and inspection tool built on
Python and Scapy. It dissects Ethernet → IP → TCP/UDP → DNS/HTTP, and
reads (does not decrypt) the plaintext SNI hostname from a TLS
ClientHello, with an optional naive port-scan heuristic.

This mirrors the design in `Network_Packet_Analyzer_Explainer.pdf`.

# Files

| File | Responsibility |
|---|---|
| `analyzer.py` | CLI entry point: argument parsing, the `sniff()` loop, display, pcap output, the authorization gate. |
| `dissector.py` | Pure functions that pull readable fields out of each protocol layer (Ethernet, IP, TCP, UDP, DNS, HTTP, TLS SNI). No side effects — just parsing. |
| `stats.py` | `SynScanDetector`: a small in-memory heuristic that flags a source IP hitting many distinct ports with bare SYNs in a short window. |

## Install

```bash
pip install -r requirements.txt
# Linux also needs libpcap for live capture:
sudo apt-get install libpcap0.8
```

## Run

Needs elevated privileges to open a raw socket (this is a kernel
restriction, not a Scapy limitation):

```bash
sudo python3 analyzer.py --iface eth0 
```

Or grant the capability once instead of using `sudo` every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
python3 analyzer.py --iface eth0 
```

### Useful flag combinations

```bash
# Only show DNS queries/responses
python3 analyzer.py --iface eth0 -l1 dns

# Only show HTTP requests and HTTPS SNI handshakes
python3 analyzer.py --iface eth0 -l http

# Capture 200 packets, save to a .pcap for later analysis in Wireshark
python3 analyzer.py --iface eth0 --count 200 --save capture.pcap

# Flag a source IP that hits >10 distinct ports with bare SYNs within the detector's window
python3 analyzer.py --iface eth0 --scan-threshold 10

# Custom BPF filter (same syntax as tcpdump)
python3 analyzer.py --iface eth0  --filter "tcp port 443"
```

Stop anytime with `Ctrl+C`; if `--save` was set, whatever was captured
up to that point is still written out.

## What it actually shows you

- **Ethernet**: source/destination MAC addresses.
- **IP**: source/destination IP, TTL, protocol number.
- **TCP**: ports and a human-readable flag meaning (`S` → "SYN (connection
  request)", `SA` → "SYN-ACK (handshake step 2)", etc.).
- **UDP**: ports and payload length.
- **DNS**: query name, and resolved IP for responses.
- **HTTP** (port 80): the request/response first line, read straight from
  the plaintext payload.
- **HTTPS (port 443)**: cannot read the encrypted payload — that's TLS
  working as intended — but the SNI hostname from the ClientHello is
  parsed directly out of the handshake header, since SNI is sent in
  plaintext by design.

## Design notes

- **Passive only.** Nothing here sends, modifies, or retransmits a single
  packet — `dissector.py` only reads fields Scapy already parsed.
- **`dissector.dissect()`** returns a plain dict per packet (only the
  layers actually present), which `analyzer.py` formats for display. You
  can also import `dissector` directly and feed it packets from anywhere
  (e.g. a saved `.pcap` you read back with `rdpcap()`).
- **`SynScanDetector`** is deliberately simple — a sliding window of
  `(timestamp, dst_port)` per source IP. It's meant to demonstrate the
  idea from the explainer doc's "Natural Next Steps" section, not to
  replace a real IDS like Suricata or Zeek.

## Known limitations (same ones called out in the explainer doc)

- Can't read HTTPS payloads — by design, not a bug.
- Single-process, single-machine; no distributed capture.
- On a switched network, you only see traffic the switch actually
  forwards to your port (broadcast/multicast/traffic addressed to you),
  not the whole LAN — promiscuous mode doesn't change that without
  port-mirroring/SPAN.
- Pure-Python parsing won't keep up with saturated multi-gigabit links
  the way a compiled tool (tshark) does.
