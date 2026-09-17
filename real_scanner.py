"""
real_scanner.py
----------------
A real, working TCP port scanner using Python's built-in `socket` library.

Legal / ethical note:
    Only scan hosts and networks you own or have explicit permission to test.
    Unauthorized port scanning may violate laws or acceptable-use policies.

Techniques implemented:
    - TCP Connect Scan (full three-way handshake) — reliable, no special
      privileges required, works on Windows/macOS/Linux.
    - Optional banner grabbing on open ports.
    - Multithreaded for speed, with a configurable worker pool.
    - Graceful handling of timeouts, refused connections, and host errors.
"""

from __future__ import annotations

import socket
import threading
import queue
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered", "error"
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class ScanResult:
    host: str
    resolved_ip: str
    results: list[PortResult] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "open"]

    @property
    def duration(self) -> float:
        return round(self.finished_at - self.started_at, 2)


class PortScanner:
    """
    A multithreaded TCP connect-scan port scanner.

    Example:
        scanner = PortScanner(timeout=0.75, max_workers=200)
        result = scanner.scan("scanme.example.com", ports=range(1, 1025))
        for p in result.open_ports:
            print(p.port, p.service, p.banner)
    """

    def __init__(
        self,
        timeout: float = 1.0,
        max_workers: int = 100,
        grab_banner: bool = True,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if max_workers <= 0:
            raise ValueError("max_workers must be > 0")
        self.timeout = timeout
        self.max_workers = max_workers
        self.grab_banner = grab_banner

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan(
        self,
        host: str,
        ports: "range | list[int]" = range(1, 1025),
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> ScanResult:
        """
        Scan `host` across `ports`. Returns a ScanResult.

        progress_callback(scanned_count, total_count) is called after
        each port finishes, if provided (useful for progress bars).
        """
        address_family, resolved_ip = self._resolve(host)

        result = ScanResult(host=host, resolved_ip=resolved_ip)
        result.started_at = time.time()

        port_list = list(ports)
        total = len(port_list)
        work_q: queue.Queue[int] = queue.Queue()
        for p in port_list:
            work_q.put(p)

        results_lock = threading.Lock()
        scanned_count = 0

        def worker() -> None:
            nonlocal scanned_count
            while True:
                try:
                    port = work_q.get_nowait()
                except queue.Empty:
                    return
                try:
                    port_result = self._scan_port(address_family, resolved_ip, port)
                except Exception as exc:
                    port_result = PortResult(port=port, state="error", error=str(exc))
                finally:
                    with results_lock:
                        result.results.append(port_result)
                        scanned_count += 1
                        if progress_callback:
                            progress_callback(scanned_count, total)
                    work_q.task_done()

        thread_count = min(self.max_workers, max(1, total))
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(thread_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        result.results.sort(key=lambda r: r.port)
        result.finished_at = time.time()
        return result

    def scan_common_ports(self, host: str, **kwargs) -> ScanResult:
        return self.scan(host, ports=sorted(COMMON_PORTS.keys()), **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve(host: str) -> tuple[int, str]:
        try:
            addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            family, _, _, _, sockaddr = addresses[0]
            return family, sockaddr[0]
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve host '{host}': {exc}") from exc

    def _scan_port(self, address_family: int, ip: str, port: int) -> PortResult:
        start = time.time()
        sock = None
        try:
            sock = socket.socket(address_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            address = (ip, port) if address_family == socket.AF_INET else (ip, port, 0, 0)
            conn_result = sock.connect_ex(address)
            latency_ms = round((time.time() - start) * 1000, 2)

            if conn_result == 0:
                service = COMMON_PORTS.get(port, "")
                banner = ""
                if self.grab_banner:
                    banner = self._grab_banner(sock)
                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    latency_ms=latency_ms,
                )
            else:
                return PortResult(port=port, state="closed", latency_ms=latency_ms)
        except socket.timeout:
            return PortResult(port=port, state="filtered", latency_ms=round(self.timeout * 1000, 2))
        except OSError:
            return PortResult(port=port, state="filtered")
        finally:
            if sock is not None:
                sock.close()

    @staticmethod
    def _grab_banner(sock: socket.socket, max_bytes: int = 128) -> str:
        try:
            sock.settimeout(0.5)
            data = sock.recv(max_bytes)
            return data.decode(errors="replace").strip()
        except (socket.timeout, OSError):
            return ""
