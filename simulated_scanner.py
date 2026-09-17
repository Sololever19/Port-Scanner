"""
simulated_scanner.py
---------------------
A fake/simulated port scanner that produces realistic-looking results
WITHOUT making any real network connections.

Useful for:
    - Demos in restricted/offline environments (e.g. sandboxes, CI, classrooms)
    - UI/UX testing of tools that consume scan results
    - Teaching how scan output is structured, without touching a real network

It reuses the same PortResult / ScanResult data classes as real_scanner.py,
so callers can swap between PortScanner and SimulatedPortScanner
interchangeably.
"""

from __future__ import annotations

import random
import time
from typing import Callable, Optional

from .real_scanner import PortResult, ScanResult, COMMON_PORTS


class SimulatedPortScanner:
    """
    Drop-in, network-free replacement for PortScanner.

    Example:
        scanner = SimulatedPortScanner(seed=42)
        result = scanner.scan("192.0.2.10", ports=range(1, 1025))
    """

    def __init__(
        self,
        timeout: float = 1.0,
        max_workers: int = 100,
        grab_banner: bool = True,
        seed: Optional[int] = None,
        open_port_ratio: float = 0.02,
    ) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.grab_banner = grab_banner
        self.open_port_ratio = open_port_ratio
        self._rng = random.Random(seed)

        self._fake_banners = {
            "SSH": "SSH-2.0-OpenSSH_9.6",
            "HTTP": "HTTP/1.1 200 OK Server: nginx/1.25.3",
            "HTTPS": "",
            "FTP": "220 (vsFTPd 3.0.5)",
            "SMTP": "220 mail.example.local ESMTP Postfix",
            "MySQL": "5.7.44-log",
            "Redis": "-ERR unknown command",
        }

    def scan(
        self,
        host: str,
        ports: "range | list[int]" = range(1, 1025),
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> ScanResult:
        # Fake, deterministic-looking "resolved IP" without any DNS lookup.
        resolved_ip = self._fake_ip(host)

        result = ScanResult(host=host, resolved_ip=resolved_ip)
        result.started_at = time.time()

        port_list = list(ports)
        total = len(port_list)

        # Always mark a handful of well-known ports "open" for a believable demo.
        guaranteed_open = {22, 80, 443}

        for i, port in enumerate(port_list, start=1):
            # tiny artificial delay so progress callbacks / UIs feel real
            time.sleep(0.0005)

            is_open = port in guaranteed_open or self._rng.random() < self.open_port_ratio

            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                banner = self._fake_banners.get(service, "") if self.grab_banner else ""
                pr = PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    latency_ms=round(self._rng.uniform(1.0, 40.0), 2),
                )
            else:
                state = "closed" if self._rng.random() > 0.05 else "filtered"
                pr = PortResult(port=port, state=state, latency_ms=round(self._rng.uniform(0.5, 5.0), 2))

            result.results.append(pr)
            if progress_callback:
                progress_callback(i, total)

        result.results.sort(key=lambda r: r.port)
        result.finished_at = time.time()
        return result

    def scan_common_ports(self, host: str, **kwargs) -> ScanResult:
        return self.scan(host, ports=sorted(COMMON_PORTS.keys()), **kwargs)

    @staticmethod
    def _fake_ip(host: str) -> str:
        # Deterministic pseudo-IP derived from the hostname string,
        # purely cosmetic — never resolves anything real.
        h = sum(ord(c) for c in host)
        return f"203.0.113.{h % 254 + 1}"
