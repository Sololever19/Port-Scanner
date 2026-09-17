#!/usr/bin/env python3
"""
main.py — Command-line interface for the port scanner project.

Usage examples:
    # Real scan of the top common ports on a host you own/administer
    python main.py scan example.com --common

    # Real scan of a custom port range with more threads
    python main.py scan 192.168.1.10 --ports 1-1024 --workers 200

    # Simulated scan (no real network traffic at all) — good for demos
    python main.py scan example.com --common --simulate

    # Save results to JSON or CSV
    python main.py scan example.com --common --output results.json
    python main.py scan example.com --common --output results.csv

Legal / ethical note:
    Only scan systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from scanner import PortScanner, SimulatedPortScanner, ScanResult, parse_ports as shared_parse_ports


def parse_ports(spec: str) -> list[int]:
    try:
        return shared_parse_ports(spec)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def print_results(result: ScanResult, show_closed: bool = False) -> None:
    print(f"\nScan report for {result.host} ({result.resolved_ip})")
    print(f"Completed in {result.duration}s — {len(result.results)} ports checked\n")

    header = f"{'PORT':<8}{'STATE':<10}{'SERVICE':<14}{'LATENCY':<10}BANNER"
    print(header)
    print("-" * len(header))

    rows = result.results if show_closed else result.open_ports
    if not rows:
        print("(no matching ports)")
    for r in rows:
        banner = (r.banner[:40] + "...") if len(r.banner) > 40 else r.banner
        print(f"{r.port:<8}{r.state:<10}{r.service:<14}{f'{r.latency_ms}ms':<10}{banner}")

    print(f"\n{len(result.open_ports)} open port(s) found.")


def save_results(result: ScanResult, path: str) -> None:
    out_path = Path(path)
    rows = [
        {
            "port": r.port,
            "state": r.state,
            "service": r.service,
            "banner": r.banner,
            "latency_ms": r.latency_ms,
        }
        for r in result.results
    ]

    if out_path.suffix.lower() == ".json":
        payload = {
            "host": result.host,
            "resolved_ip": result.resolved_ip,
            "duration_seconds": result.duration,
            "results": rows,
        }
        out_path.write_text(json.dumps(payload, indent=2))
    elif out_path.suffix.lower() == ".csv":
        with out_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner", "latency_ms"])
            writer.writeheader()
            writer.writerows(rows)
    else:
        raise ValueError("Output file must end in .json or .csv")

    print(f"Results saved to {out_path.resolve()}")


def progress_bar(scanned: int, total: int, bar_len: int = 30) -> None:
    filled = int(bar_len * scanned / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\rScanning [{bar}] {scanned}/{total}")
    sys.stdout.flush()
    if scanned == total:
        sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="A real (and optionally simulated) TCP port scanner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a host for open ports")
    scan_p.add_argument("host", help="Hostname or IP address to scan")

    port_group = scan_p.add_mutually_exclusive_group()
    port_group.add_argument(
        "--ports", type=str, default=None,
        help="Port spec, e.g. '80', '1-1024', '22,80,443,8080-8090'"
    )
    port_group.add_argument(
        "--common", action="store_true",
        help="Scan a curated list of common/well-known ports only"
    )

    scan_p.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout in seconds (default: 1.0)")
    scan_p.add_argument("--workers", type=int, default=100, help="Number of concurrent worker threads (default: 100)")
    scan_p.add_argument("--no-banner", action="store_true", help="Disable banner grabbing on open ports")
    scan_p.add_argument("--show-closed", action="store_true", help="Also list closed/filtered ports")
    scan_p.add_argument("--simulate", action="store_true", help="Run a simulated scan (no real network traffic)")
    scan_p.add_argument("--seed", type=int, default=None, help="Random seed for reproducible simulated scans")
    scan_p.add_argument("--output", type=str, default=None, help="Save results to a .json or .csv file")
    scan_p.add_argument("--quiet", action="store_true", help="Suppress the live progress bar")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        if args.common:
            ports = None  # scanner will use scan_common_ports
        elif args.ports:
            ports = parse_ports(args.ports)
        else:
            ports = list(range(1, 1025))  # default: first 1024 ports

        callback = None if args.quiet else progress_bar

        try:
            if args.simulate:
                scanner = SimulatedPortScanner(
                    timeout=args.timeout,
                    max_workers=args.workers,
                    grab_banner=not args.no_banner,
                    seed=args.seed,
                )
            else:
                scanner = PortScanner(
                    timeout=args.timeout,
                    max_workers=args.workers,
                    grab_banner=not args.no_banner,
                )

            if args.common:
                result = scanner.scan_common_ports(args.host, progress_callback=callback)
            else:
                result = scanner.scan(args.host, ports=ports, progress_callback=callback)

        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\nScan interrupted by user.", file=sys.stderr)
            return 130

        print_results(result, show_closed=args.show_closed)

        if args.output:
            save_results(result, args.output)

        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
