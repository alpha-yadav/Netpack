"""
stats.py
--------
Lightweight, in-memory traffic heuristics. Nothing here blocks or
modifies traffic -- it just counts things and raises a flag when a
simple threshold is crossed, e.g. one source IP sending an unusually
high number of SYNs to many destination ports in a short window
(a classic, if naive, port-scan signature).

This is intentionally simple: a real IDS uses much more nuance. The
goal here is to demonstrate the idea, not replace Snort/Suricata/Zeek.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple


@dataclass
class ScanAlert:
    src_ip: str
    distinct_ports: int
    window_seconds: float
    message: str


class SynScanDetector:
    """
    Tracks (src_ip -> distinct destination ports hit with a bare SYN)
    within a rolling time window. Fires an alert if a single source
    touches more than `port_threshold` distinct ports within
    `window_seconds`.
    """

    def __init__(self, port_threshold: int = 15, window_seconds: float = 10.0):
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        # src_ip -> deque[(timestamp, dst_port)]
        self._events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._already_alerted: set = set()

    def observe(self, src_ip: str, dst_port: int, tcp_flags: str) -> Optional[ScanAlert]:
        """Feed one TCP packet's (src_ip, dst_port, flags) in. Returns a
        ScanAlert if this observation pushed src_ip over the threshold,
        else None. A given src_ip only alerts once per window to avoid
        spamming output."""
        if tcp_flags != "S":  # only bare SYNs (connection attempts) count
            return None

        now = time.monotonic()
        events = self._events[src_ip]
        events.append((now, dst_port))

        # Drop events outside the rolling window
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

        distinct_ports = {port for _, port in events}
        if len(distinct_ports) > self.port_threshold:
            if src_ip in self._already_alerted:
                return None
            self._already_alerted.add(src_ip)
            return ScanAlert(
                src_ip=src_ip,
                distinct_ports=len(distinct_ports),
                window_seconds=self.window_seconds,
                message=(
                    f"Possible port scan: {src_ip} hit {len(distinct_ports)} distinct "
                    f"ports with bare SYNs in {self.window_seconds:.0f}s"
                ),
            )

        # Allow re-alerting once activity has cooled off and resumed
        if not distinct_ports:
            self._already_alerted.discard(src_ip)

        return None
