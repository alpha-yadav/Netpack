"""
dissector.py
------------
Layer-by-layer packet dissection. Each function pulls the fields that
matter from one protocol layer and returns them as a plain dict, so the
caller (analyzer.py) can decide how to display, log, or filter on them.

Nothing here modifies or retransmits anything -- it only reads fields
that Scapy has already parsed out of the packet bytes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

# TCP control flag bits -> human-readable handshake/connection-state labels.
# Scapy exposes pkt[TCP].flags as a string like "S", "SA", "A", "FA", "R", etc.
TCP_FLAG_MEANINGS = {
    "S": "SYN (connection request)",
    "SA": "SYN-ACK (handshake step 2)",
    "A": "ACK",
    "PA": "PSH-ACK (data push)",
    "FA": "FIN-ACK (graceful close)",
    "F": "FIN (graceful close)",
    "R": "RST (connection reset/refused)",
    "RA": "RST-ACK",
}


def dissect_ethernet(pkt) -> Optional[Dict[str, Any]]:
    if not pkt.haslayer(Ether):
        return None
    eth = pkt[Ether]
    return {"src_mac": eth.src, "dst_mac": eth.dst}


def dissect_ip(pkt) -> Optional[Dict[str, Any]]:
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    return {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "ttl": ip.ttl,
        "proto_num": ip.proto,  # 6 = TCP, 17 = UDP
    }


def dissect_tcp(pkt) -> Optional[Dict[str, Any]]:
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    flag_str = str(tcp.flags)
    return {
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "flags": flag_str,
        "flags_meaning": TCP_FLAG_MEANINGS.get(flag_str, flag_str),
        "seq": tcp.seq,
        "ack": tcp.ack,
    }


def dissect_udp(pkt) -> Optional[Dict[str, Any]]:
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    return {"src_port": udp.sport, "dst_port": udp.dport, "length": udp.len}


def dissect_dns(pkt) -> Optional[Dict[str, Any]]:
    if not pkt.haslayer(DNS):
        return None
    info: Dict[str, Any] = {}
    if pkt.haslayer(DNSQR):
        try:
            info["query_name"] = pkt[DNSQR].qname.decode(errors="ignore")
        except Exception:
            info["query_name"] = str(pkt[DNSQR].qname)
    if pkt.haslayer(DNSRR):
        try:
            info["resolved_to"] = pkt[DNSRR].rdata
        except Exception:
            pass
    return info or None


def dissect_http(pkt) -> Optional[Dict[str, Any]]:
    """Plaintext HTTP on port 80: the request/response line is readable
    directly in the TCP payload (Raw layer)."""
    if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
        return None
    if pkt[TCP].dport != 80 and pkt[TCP].sport != 80:
        return None
    try:
        payload = pkt[Raw].load.decode(errors="ignore")
    except Exception:
        return None
    first_line = payload.splitlines()[0] if payload else ""
    if first_line.startswith(("GET", "POST", "HEAD", "PUT", "DELETE", "HTTP/")):
        return {"first_line": first_line}
    return None


def extract_tls_sni(pkt) -> Optional[str]:
    """
    Best-effort extraction of the Server Name Indication (SNI) hostname
    from a TLS ClientHello. SNI travels in plaintext even on an otherwise
    encrypted HTTPS connection -- that's by design, not a flaw -- so
    reading it here is the same kind of passive observation any monitoring
    tool (e.g. Zeek, ja3) performs. This does NOT decrypt anything; it
    only parses the handshake's unencrypted header fields.

    Returns the hostname string, or None if this isn't a parseable
    ClientHello with an SNI extension.
    """
    if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
        return None
    if pkt[TCP].dport != 443:
        return None

    data = bytes(pkt[Raw].load)
    try:
        # TLS record header: type(1) + version(2) + length(2)
        if len(data) < 6 or data[0] != 0x16:  # 0x16 = Handshake record
            return None
        # Handshake header: msg_type(1) + length(3)
        if data[5] != 0x01:  # 0x01 = ClientHello
            return None

        pos = 9  # skip record header (5) + handshake header (4)
        pos += 2  # client_version
        pos += 32  # random
        session_id_len = data[pos]
        pos += 1 + session_id_len
        cipher_suites_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2 + cipher_suites_len
        compression_len = data[pos]
        pos += 1 + compression_len

        if pos >= len(data):
            return None
        extensions_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        end = pos + extensions_len

        while pos < end:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            ext_data = data[pos + 4 : pos + 4 + ext_len]
            if ext_type == 0x00:  # server_name extension
                # server_name_list_len(2) + type(1) + name_len(2) + name
                name_len = int.from_bytes(ext_data[3:5], "big")
                hostname = ext_data[5 : 5 + name_len].decode(errors="ignore")
                return hostname or None
            pos += 4 + ext_len
    except (IndexError, ValueError):
        return None
    return None


def dissect(pkt) -> Dict[str, Any]:
    """Run every layer dissector against one packet and return whatever
    layers were actually present, keyed by layer name."""
    result: Dict[str, Any] = {}

    eth = dissect_ethernet(pkt)
    if eth:
        result["ethernet"] = eth

    ip = dissect_ip(pkt)
    if ip:
        result["ip"] = ip

    tcp = dissect_tcp(pkt)
    if tcp:
        result["tcp"] = tcp

    udp = dissect_udp(pkt)
    if udp:
        result["udp"] = udp

    dns = dissect_dns(pkt)
    if dns:
        result["dns"] = dns

    http = dissect_http(pkt)
    if http:
        result["http"] = http

    if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
        sni = extract_tls_sni(pkt)
        if sni:
            result["tls_sni"] = sni

    return result
