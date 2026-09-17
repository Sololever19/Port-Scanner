#!/usr/bin/env python3
"""
app.py — Web application front-end for the port scanner.

Run it with:
    python app.py

Then open http://127.0.0.1:5000 in your browser.

This wraps the same PortScanner / SimulatedPortScanner classes used by the
CLI (main.py) — no scanning logic is duplicated, the web app just exposes
it over a small JSON API and a browser UI.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
import socket
import threading

from flask import Flask, jsonify, render_template, request

from scanner import PortScanner, SimulatedPortScanner, COMMON_PORTS, parse_ports

app = Flask(__name__)

MAX_PORTS_PER_SCAN = 2000  # safety cap so a browser request can't request a 65535-port scan and hang
MAX_CONCURRENT_SCANS = 4
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$")
scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("Host is required.")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not HOSTNAME_RE.match(host):
        raise ValueError("That doesn't look like a valid hostname or IP address.")
    return host


@app.route("/")
def index():
    return render_template("index.html", common_ports=sorted(COMMON_PORTS.items()))


@app.route("/netpulse")
def netpulse():
    return render_template("netpulse.html", common_ports=sorted(COMMON_PORTS.items()))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    try:
        host = validate_host(data.get("host", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    mode = data.get("mode", "simulate")  # "real" or "simulate"
    port_spec = data.get("ports", "common")  # "common" or a spec string
    if mode not in {"real", "simulate"}:
        return jsonify({"error": "Mode must be 'real' or 'simulate'."}), 400

    try:
        if port_spec == "common":
            ports = sorted(COMMON_PORTS.keys())
        else:
            ports = parse_ports(port_spec)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    if len(ports) > MAX_PORTS_PER_SCAN:
        return jsonify({
            "error": f"Too many ports requested ({len(ports)}). "
                     f"Max is {MAX_PORTS_PER_SCAN} per scan in this web UI."
        }), 400

    try:
        timeout = float(data.get("timeout", 0.6))
        workers = int(data.get("workers", 150))
    except (TypeError, ValueError):
        return jsonify({"error": "Timeout and workers must be numeric values."}), 400
    if not math.isfinite(timeout) or workers < 1:
        return jsonify({"error": "Timeout and workers must be finite values."}), 400
    timeout = max(0.05, min(timeout, 5.0))
    workers = max(1, min(workers, 300))

    if not scan_slots.acquire(blocking=False):
        return jsonify({"error": "Too many scans are running. Try again shortly."}), 429
    try:
        if mode == "real":
            scanner = PortScanner(timeout=timeout, max_workers=workers, grab_banner=True)
        else:
            scanner = SimulatedPortScanner(timeout=timeout, max_workers=workers, grab_banner=True)

        result = scanner.scan(host, ports=ports)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except socket.error as exc:
        return jsonify({"error": f"Network error: {exc}"}), 502
    finally:
        scan_slots.release()

    return jsonify({
        "host": result.host,
        "resolved_ip": result.resolved_ip,
        "duration": result.duration,
        "mode": mode,
        "results": [
            {
                "port": r.port,
                "state": r.state,
                "service": r.service,
                "banner": r.banner,
                "latency_ms": r.latency_ms,
                "error": r.error,
            }
            for r in result.results
        ],
    })


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1", port=5000)
