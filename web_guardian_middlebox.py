#!/usr/bin/env python3

"""
WebGuardian Middlebox
=====================

This module evolves the CS456 Part D middlebox into a resume-ready web
security project. It passively inspects HTTP traffic at layer-2, detects
common web attack signatures (SQL injection, XSS, command injection, path
traversal), and can actively terminate suspicious TCP sessions by injecting
TCP RST packets. Events are logged with rich context so they can feed into
dashboards or SIEM tooling.

Key ideas:
    * Leverages Scapy for low-level packet capture and reaction.
    * Provides a modular attack-signature engine with explainable output.
    * Demonstrates active defense by blocking flagged traffic on demand.
"""

import argparse
import json
import logging
import os
import re
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Pattern, Set

from scapy.all import IP, TCP, Raw, sniff, send  # type: ignore


# -------------------------- Signature Definitions -------------------------- #


@dataclass(frozen=True)
class HttpAttackSignature:
    """Lightweight container for regex-based HTTP attack detection."""

    name: str
    pattern: str
    description: str
    severity: str = "medium"
    compiled: Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "compiled", re.compile(self.pattern, re.IGNORECASE))

    def matches(self, text: str) -> bool:
        return bool(self.compiled.search(text))


DEFAULT_SIGNATURES: List[HttpAttackSignature] = [
    HttpAttackSignature(
        name="SQL Injection",
        pattern=r"(?:')\s*or\s+1=1|union\s+select|information_schema|sleep\(\d+\)",
        description="Classic SQLi payload patterns attempting to bypass auth or extract schema data.",
        severity="high",
    ),
    HttpAttackSignature(
        name="Cross-Site Scripting",
        pattern=r"<\s*script|onerror\s*=|javascript:",
        description="Inline script execution hints at reflective or stored XSS probes.",
        severity="high",
    ),
    HttpAttackSignature(
        name="Command Injection",
        pattern=r"(?:;|\|\|?)\s*(?:cat|ls|id|whoami|nc|bash|sh)\b",
        description="Shell metacharacters chained with common reconnaissance commands.",
        severity="critical",
    ),
    HttpAttackSignature(
        name="Path Traversal",
        pattern=r"\.\./\.\.|etc/passwd|boot.ini",
        description="Directory traversal probes that try to escape the web root.",
        severity="medium",
    ),
    HttpAttackSignature(
        name="Deserialization Gadget",
        pattern=r"__\w+__|php://input|(?:Base64|base64)Decode",
        description="Indicators of unsafe deserialization or gadget chains.",
        severity="medium",
    ),
]


# ------------------------------ Event Schema ------------------------------ #


@dataclass
class SecurityEvent:
    """Captured metadata for a suspicious HTTP transaction."""

    timestamp: float
    signature: HttpAttackSignature
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    http_summary: str
    raw_excerpt: str
    blocked: bool

    def to_json(self) -> str:
        payload = {
            "timestamp": self.timestamp,
            "signature": self.signature.name,
            "severity": self.signature.severity,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "http_summary": self.http_summary,
            "raw_excerpt": self.raw_excerpt,
            "blocked": self.blocked,
            "description": self.signature.description,
        }
        return json.dumps(payload)


# ----------------------------- Middlebox Core ----------------------------- #


class WebGuardianMiddlebox:
    """
    Sniffs HTTP traffic on the specified interface, detects malicious patterns,
    and optionally fires active defenses by terminating suspect sessions.
    """

    def __init__(
        self,
        iface: str,
        http_ports: Iterable[int],
        signatures: Iterable[HttpAttackSignature],
        log_path: str,
        active_block: bool = False,
        stdout_logger: Optional[Callable[[SecurityEvent], None]] = None,
    ) -> None:
        self.iface = iface
        self.http_ports: Set[int] = {int(p) for p in http_ports}
        self.signatures = list(signatures)
        self.log_path = log_path
        self.active_block = active_block
        self.stdout_logger = stdout_logger
        self._stop_event = threading.Event()

        self._setup_logging()
        self._log.info(
            "Initialized WebGuardian on iface=%s watching ports=%s (active_block=%s)",
            iface,
            sorted(self.http_ports),
            self.active_block,
        )

    def _setup_logging(self) -> None:
        log_dir = os.path.dirname(self.log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        self._log = logging.getLogger("webguardian")
        self._log.setLevel(logging.INFO)
        # Avoid duplicated handlers if multiple instances are created
        if not self._log.handlers:
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S"
            )
            file_handler = logging.FileHandler(self.log_path, mode="a")
            file_handler.setFormatter(formatter)
            self._log.addHandler(file_handler)

    # ---------------------------- Public API --------------------------- #

    def start(self) -> None:
        """Begin packet capture until interrupted."""
        self._register_signal_handlers()
        self._log.info("Starting packet capture on %s", self.iface)
        try:
            sniff(
                iface=self.iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            self._log.error("Root privileges are required to sniff packets.")
            raise
        finally:
            self._log.info("Packet capture stopped.")

    def stop(self) -> None:
        """Signal the sniffer loop to terminate."""
        self._stop_event.set()

    # -------------------------- Packet Handling ------------------------ #

    def _process_packet(self, packet) -> None:
        if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        payload_bytes: bytes = bytes(tcp_layer.payload)
        if not payload_bytes:
            return

        if tcp_layer.dport not in self.http_ports and tcp_layer.sport not in self.http_ports:
            return

        request_text = payload_bytes.decode("utf-8", errors="ignore")
        if not self._looks_like_http(request_text):
            return

        matched_signature = self._match_signature(request_text)
        if not matched_signature:
            return

        event = SecurityEvent(
            timestamp=time.time(),
            signature=matched_signature,
            src_ip=ip_layer.src,
            src_port=tcp_layer.sport,
            dst_ip=ip_layer.dst,
            dst_port=tcp_layer.dport,
            http_summary=self._summarize_http(request_text),
            raw_excerpt=self._sanitize_excerpt(request_text),
            blocked=False,
        )

        if self.active_block:
            event.blocked = self._terminate_session(packet)

        self._record_event(event)

    # ------------------------- Detection Helpers ----------------------- #

    def _looks_like_http(self, text: str) -> bool:
        # Basic heuristic: HTTP request line or response
        return text.startswith(("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")) or "HTTP/" in text

    def _match_signature(self, text: str) -> Optional[HttpAttackSignature]:
        for signature in self.signatures:
            if signature.matches(text):
                return signature
        return None

    def _summarize_http(self, text: str) -> str:
        first_line = text.splitlines()[0] if text else ""
        return first_line[:200]

    def _sanitize_excerpt(self, text: str, limit: int = 120) -> str:
        excerpt = text.replace("\n", "\\n")
        if len(excerpt) > limit:
            excerpt = excerpt[:limit] + "..."
        return excerpt

    # ------------------------- Active Response ------------------------- #

    def _terminate_session(self, packet) -> bool:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        payload_len = len(bytes(tcp_layer.payload))

        flags = tcp_layer.flags
        if "S" in flags and "A" not in flags:
            # Ignore bare SYN packets; no HTTP payload to evaluate.
            return False

        try:
            # RST to server
            rst_to_server = IP(src=ip_layer.src, dst=ip_layer.dst) / TCP(
                sport=tcp_layer.sport,
                dport=tcp_layer.dport,
                flags="R",
                seq=tcp_layer.seq + payload_len,
                ack=tcp_layer.ack,
            )
            # RST to client
            rst_to_client = IP(src=ip_layer.dst, dst=ip_layer.src) / TCP(
                sport=tcp_layer.dport,
                dport=tcp_layer.sport,
                flags="R",
                seq=tcp_layer.ack,
                ack=0,
            )
            send(rst_to_server, verbose=False)
            send(rst_to_client, verbose=False)
            return True
        except Exception as exc:
            self._log.exception("Failed to send TCP RST packets: %s", exc)
            return False

    # ------------------------- Event Recording ------------------------- #

    def _record_event(self, event: SecurityEvent) -> None:
        self._log.info(event.to_json())
        if self.stdout_logger:
            self.stdout_logger(event)

    # ---------------------------- Utilities ---------------------------- #

    def _register_signal_handlers(self) -> None:
        def _handle_signal(signum, _frame):
            self._log.info("Received signal %s, shutting down.", signum)
            self.stop()

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)


# ---------------------------- CLI Entrypoint ------------------------------ #


def _cli_logger(event: SecurityEvent) -> None:
    summary = (
        f"[{event.signature.severity.upper():>8}] "
        f"{event.signature.name} detected "
        f"{event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port} | "
        f"{event.http_summary}"
    )
    print(summary)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect HTTP traffic in real-time and detect common web attacks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "iface",
        help="Interface to sniff (e.g., eth0, h3-eth0). Requires root privileges.",
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[80, 8080, 8000],
        help="HTTP ports to inspect.",
    )
    parser.add_argument(
        "--log-path",
        default="logs/webguardian_events.log",
        help="Path for JSONL security event logs.",
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Actively tear down suspicious TCP sessions with RST packets.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    middlebox = WebGuardianMiddlebox(
        iface=args.iface,
        http_ports=args.ports,
        signatures=DEFAULT_SIGNATURES,
        log_path=args.log_path,
        active_block=args.block,
        stdout_logger=_cli_logger,
    )
    middlebox.start()


if __name__ == "__main__":
    main()

