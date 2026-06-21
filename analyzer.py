#!/usr/bin/env python3
"""
================================================================
AUTHORIZATION REQUIRED
================================================================
Only run this against:
  - hardware/networks you personally own and control, or
  - infrastructure you have explicit, documented authorization to
    test (e.g. a signed pentest scope, a university lab assignment), or
  - isolated lab/VM environments with no real third-party traffic.
<<<<<<< HEAD

=======
>>>>>>> 1123ddddafbead2b8f8aa20c1202c3fc8f43f119
================================================================
"""

import argparse
import sys
import time
from typing import Optional

from scapy.all import IP, TCP, conf, sniff, wrpcap

import dissector
from stats import SynScanDetector


class PacketAnalyzer:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.captured = []  # only populated if --pcap-out is set
        self.packet_count = 0
        self.scan_detector = (
            SynScanDetector(port_threshold=args.scan_threshold) if args.detect_scans else None
        )
        self.start_time = time.monotonic()

    # -- per-packet callback handed to scapy.sniff() ------------------------
    def handle_packet(self, pkt) -> None:
        self.packet_count += 1

        if self.args.pcap_out:
            self.captured.append(pkt)

        layers = dissector.dissect(pkt)
        if not layers:
            return  # nothing we recognize (e.g. ARP, non-IP traffic) -- skip quietly

        if self.args.dns_only and "dns" not in layers:
            return
        if self.args.http_only and "http" not in layers and "tls_sni" not in layers:
            return

        self._print_packet(layers)

        if self.scan_detector and "tcp" in layers and "ip" in layers:
            alert = self.scan_detector.observe(
                src_ip=layers["ip"]["src_ip"],
                dst_port=layers["tcp"]["dst_port"],
                tcp_flags=layers["tcp"]["flags"],
            )
            if alert:
                print(f"  !! ALERT: {alert.message}")

    # -- display --------------------------------------------------------------
    def _print_packet(self, layers: dict) -> None:
        parts = [f"#{self.packet_count}"]

        if "ip" in layers:
            ip = layers["ip"]
            parts.append(f"{ip['src_ip']} -> {ip['dst_ip']} (ttl={ip['ttl']})")

        if "tcp" in layers:
            tcp = layers["tcp"]
            parts.append(
                f"TCP {tcp['src_port']}->{tcp['dst_port']} [{tcp['flags']}] "
                f"({tcp['flags_meaning']})"
            )
        elif "udp" in layers:
            udp = layers["udp"]
            parts.append(f"UDP {udp['src_port']}->{udp['dst_port']} len={udp['length']}")

        if "dns" in layers:
            dns = layers["dns"]
            if "query_name" in dns:
                parts.append(f"DNS query: {dns['query_name']}")
            if "resolved_to" in dns:
                parts.append(f"DNS resolved -> {dns['resolved_to']}")

        if "http" in layers:
            parts.append(f"HTTP: {layers['http']['first_line']}")

        if "tls_sni" in layers:
            parts.append(f"TLS SNI: {layers['tls_sni']}")

        print("  ".join(parts))

    # -- run -------------------------------------------------------------
    def run(self) -> None:
        print(f"[*] Listening on iface={self.args.iface or 'any'}  "
              f"filter='{self.args.filter}'  "
              f"(Ctrl+C to stop)\n")
        try:
            sniff(
                iface=self.args.iface,
                filter=self.args.filter,
                prn=self.handle_packet,
                count=self.args.count,
                timeout=self.args.timeout,
                store=0,
            )
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print(
                "\n[!] Permission denied opening a raw socket.\n"
                "    Raw packet capture needs elevated privileges. Run with:\n"
                "      sudo python3 analyzer.py ...\n"
                "    or grant the capability once instead of using sudo every time:\n"
                "      sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)\n",
                file=sys.stderr,
            )
            sys.exit(1)
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        elapsed = time.monotonic() - self.start_time
        print(f"\n[*] Stopped. Captured {self.packet_count} packets in {elapsed:.1f}s.")
        if self.args.pcap_out and self.captured:
            wrpcap(self.args.pcap_out, self.captured)
            print(f"[*] Wrote {len(self.captured)} packets to {self.args.pcap_out}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Real-time packet capture & inspection tool (Scapy-based). "
        "Passive/read-only. Use only on networks you own or are authorized to monitor.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--iface", default=None, help="Network interface (e.g. eth0, wlan0). Default: all interfaces.")
    parser.add_argument(
        "--filter",
        default="tcp or udp",
        help="BPF filter string, e.g. 'tcp port 80', 'udp port 53'.",
    )
    parser.add_argument("--count", type=int, default=0, help="Stop after this many packets (0 = unlimited).")
    parser.add_argument("--timeout", type=int, default=None, help="Stop after this many seconds.")
    parser.add_argument("--pcap-out", default=None, help="Write captured packets to this .pcap file on exit.")
    parser.add_argument("--dns-only", action="store_true", help="Only display packets containing DNS traffic.")
    parser.add_argument("--http-only", action="store_true", help="Only display HTTP requests / HTTPS SNI handshakes.")
    parser.add_argument(
        "--detect-scans",
        action="store_true",
        help="Enable a basic heuristic that flags a source IP sending bare SYNs to many distinct ports quickly.",
    )
    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=15,
        help="Distinct ports within the detector's window before a scan alert fires.",
    )
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Required flag confirming you own this network or have written authorization to monitor it.",
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        print(
            "[!] Refusing to start: pass --i-have-authorization to confirm you own this\n"
            "    network/hardware, or have explicit written authorization to monitor it,\n"
            "    or are running inside an isolated lab/VM with no third-party traffic.\n"
            "    See the docstring at the top of this file for details.",
            file=sys.stderr,
        )
        return 1

    if args.dns_only and not args.filter:
        args.filter = "udp port 53"

    analyzer = PacketAnalyzer(args)
    analyzer.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
