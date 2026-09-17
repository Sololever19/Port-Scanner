"""Shared port specification parsing for the CLI and web API."""

from __future__ import annotations


def parse_ports(spec: str) -> list[int]:
    """Parse ports such as ``80``, ``1-1024``, or ``22,80,443``."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Port specification must not be empty.")

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise ValueError("Port specification contains an empty item.")
        try:
            if "-" in chunk:
                parts = chunk.split("-")
                if len(parts) != 2 or not all(part.strip() for part in parts):
                    raise ValueError
                start, end = (int(part.strip()) for part in parts)
                if start > end:
                    raise ValueError(f"Invalid range '{chunk}': start is greater than end.")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(chunk))
        except ValueError as exc:
            if str(exc).startswith("Invalid range"):
                raise
            raise ValueError(f"Invalid port specification item '{chunk}'.") from exc

    for port in ports:
        if not 0 < port <= 65535:
            raise ValueError(f"Port {port} is out of range (must be 1-65535).")
    return sorted(ports)
