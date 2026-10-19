from __future__ import annotations

import ipaddress
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Callable

from scapy.config import conf
conf.use_pcap = True

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, get_if_list
except Exception as exc:
    AsyncSniffer = None
    IP = IPv6 = TCP = UDP = ICMP = DNS = DNSQR = None
    get_if_list = lambda: []
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


class LiveCaptureManager:
    """Passive Npcap capture. Metadata only; never injects packets."""

    def __init__(self, capture_dir: Path):
        self.capture_dir = Path(capture_dir)
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.sniffer = None
        self.interface = None
        self.started_at = None
        self.packet_count = 0
        self.byte_count = 0
        self.protocols = Counter()
        self.talkers = Counter()
        self.recent = deque(maxlen=120)
        self.lock = threading.Lock()
        self.last_packet_at = 0.0
        self._callback: Callable[[dict], None] | None = None

    def interfaces(self):
        if _IMPORT_ERROR:
            return []
        return [{"name": name, "display": name} for name in get_if_list()]

    @staticmethod
    def _direction(src: str) -> str:
        try:
            ip = ipaddress.ip_address(src)
            return "egress" if ip.is_private or ip.is_loopback else "ingress"
        except Exception:
            return "unknown"

    @staticmethod
    def _dns_query(pkt):
        try:
            if DNS in pkt and getattr(pkt[DNS], "qd", None) and DNSQR in pkt:
                q = pkt[DNSQR].qname
                if isinstance(q, bytes):
                    q = q.decode("idna", errors="ignore")
                return str(q).rstrip(".")
        except Exception:
            return None
        return None

    def _packet_event(self, pkt):
        now = time.time()
        length = len(pkt)
        src = dst = "—"
        proto = "OTHER"
        sport = dport = None

        try:
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst

            if TCP in pkt:
                proto = "TCP"; sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"; sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            elif ICMP in pkt:
                proto = "ICMP"
            elif DNS in pkt:
                proto = "DNS"

            event = {
                "timestamp": now,
                "source_ip": src,
                "destination_ip": dst,
                "source_port": sport,
                "destination_port": dport,
                "protocol": proto,
                "length": length,
                "direction": self._direction(src),
                "dns_query": self._dns_query(pkt),
            }

            with self.lock:
                self.packet_count += 1
                self.byte_count += length
                self.protocols[proto] += 1
                if src != "—":
                    self.talkers[src] += 1
                self.last_packet_at = now
                self.recent.appendleft(event)

            if self._callback:
                try:
                    self._callback(event)
                except Exception as exc:
                    print(f"[LIVE] callback error: {exc}")

        except Exception as exc:
            print(f"[LIVE] packet parse error: {exc}")

    def start(self, iface: str, callback: Callable[[dict], None]):
        if _IMPORT_ERROR or AsyncSniffer is None:
            raise RuntimeError(f"Scapy/Npcap unavailable: {_IMPORT_ERROR}")
        if self.running:
            return self.status()

        self.interface = iface
        self.started_at = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.protocols.clear()
        self.talkers.clear()
        self.recent.clear()
        self._callback = callback

        # conf.use_pcap is deliberately set before AsyncSniffer is created.
        conf.use_pcap = True
        self.sniffer = AsyncSniffer(
            iface=iface,
            prn=self._packet_event,
            store=False,
        )
        try:
            self.sniffer.start()
        except Exception:
            self.sniffer = None
            raise

        print(f"[LIVE] capture started: {iface} | pcap={conf.use_pcap}")
        return self.status()

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception as exc:
                print(f"[LIVE] stop error: {exc}")
        self.sniffer = None
        self._callback = None
        return self.status()

    @property
    def running(self):
        return self.sniffer is not None and getattr(self.sniffer, "running", False)

    def status(self):
        with self.lock:
            elapsed = max(0.001, time.time() - self.started_at) if self.started_at else 0.001
            return {
                "running": self.running,
                "interface": self.interface,
                "uptime_sec": round(elapsed, 1),
                "packets": self.packet_count,
                "bytes": self.byte_count,
                "packets_per_sec": round(self.packet_count / elapsed, 2),
                "mbps": round((self.byte_count * 8 / elapsed) / 1_000_000, 3),
                "protocols": dict(self.protocols),
                "top_talkers": self.talkers.most_common(8),
                "recent": list(self.recent)[:50],
                "last_packet_at": self.last_packet_at,
                "npcap_enabled": bool(conf.use_pcap),
            }
