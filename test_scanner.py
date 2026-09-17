import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import unittest
from unittest.mock import patch, MagicMock

import socket

from scanner import PortScanner, SimulatedPortScanner
from main import parse_ports
from app import app


class TestParsePorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_mixed_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_mixed_with_range(self):
        self.assertEqual(parse_ports("22,80-82"), [22, 80, 81, 82])

    def test_dedupes(self):
        self.assertEqual(parse_ports("80,80,80-82"), [80, 81, 82])

    def test_invalid_port_raises(self):
        with self.assertRaises(Exception):
            parse_ports("70000")

    def test_invalid_range_raises(self):
        with self.assertRaises(Exception):
            parse_ports("100-10")

    def test_malformed_spec_raises_cleanly(self):
        with self.assertRaises(Exception):
            parse_ports("80-")
        with self.assertRaises(Exception):
            parse_ports("80,,90")


class TestSimulatedScanner(unittest.TestCase):
    def test_scan_returns_result_for_every_port(self):
        scanner = SimulatedPortScanner(seed=1)
        result = scanner.scan("test.local", ports=range(1, 51))
        self.assertEqual(len(result.results), 50)
        self.assertEqual(result.host, "test.local")

    def test_common_ports_include_ssh_http_https(self):
        scanner = SimulatedPortScanner(seed=1)
        result = scanner.scan_common_ports("test.local")
        open_ports = {r.port for r in result.open_ports}
        self.assertTrue({22, 80, 443}.issubset(open_ports))

    def test_deterministic_with_seed(self):
        s1 = SimulatedPortScanner(seed=99)
        s2 = SimulatedPortScanner(seed=99)
        r1 = s1.scan("host", ports=range(1, 30))
        r2 = s2.scan("host", ports=range(1, 30))
        states1 = [(r.port, r.state) for r in r1.results]
        states2 = [(r.port, r.state) for r in r2.results]
        self.assertEqual(states1, states2)


class TestRealScannerWithMockedSockets(unittest.TestCase):
    """
    Verifies PortScanner's logic without touching a real network,
    by mocking socket.socket.
    """

    @patch("scanner.real_scanner.socket.getaddrinfo", return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ])
    @patch("scanner.real_scanner.socket.socket")
    def test_open_port_detected(self, mock_socket_cls, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # 0 == success/open
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6\n"
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner(timeout=0.1, max_workers=5)
        result = scanner.scan("localhost", ports=[22])

        self.assertEqual(len(result.results), 1)
        self.assertEqual(result.results[0].state, "open")
        self.assertEqual(result.results[0].port, 22)

    @patch("scanner.real_scanner.socket.getaddrinfo", return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ])
    @patch("scanner.real_scanner.socket.socket")
    def test_closed_port_detected(self, mock_socket_cls, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED-ish, non-zero == closed
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner(timeout=0.1, max_workers=5, grab_banner=False)
        result = scanner.scan("localhost", ports=[9999])

        self.assertEqual(result.results[0].state, "closed")

    @patch("scanner.real_scanner.socket.getaddrinfo", side_effect=socket.gaierror("DNS fail"))
    def test_unresolvable_host_raises(self, mock_resolve):
        scanner = PortScanner()
        with self.assertRaises(ValueError):
            scanner.scan("does-not-exist.invalid", ports=[80])

    @patch("scanner.real_scanner.socket.getaddrinfo", return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ])
    def test_worker_exception_is_reported_without_losing_other_ports(self, mock_resolve):
        scanner = PortScanner(timeout=0.1, max_workers=1, grab_banner=False)
        real_scan_port = scanner._scan_port

        def fail_one_port(family, ip, port):
            if port == 80:
                raise RuntimeError("socket failed")
            return real_scan_port(family, ip, port)

        with patch.object(scanner, "_scan_port", side_effect=fail_one_port):
            result = scanner.scan("localhost", ports=[80, 81])
        self.assertEqual(len(result.results), 2)
        self.assertEqual(result.results[0].state, "error")


class TestApi(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_rejects_invalid_request_values(self):
        response = self.client.post("/api/scan", json={"host": "localhost", "mode": "bad"})
        self.assertEqual(response.status_code, 400)

        response = self.client.post("/api/scan", json={"host": "localhost", "timeout": "bad"})
        self.assertEqual(response.status_code, 400)

        response = self.client.post("/api/scan", json={"host": "localhost", "ports": "80,,90"})
        self.assertEqual(response.status_code, 400)

    def test_simulated_scan_returns_error_field(self):
        response = self.client.post("/api/scan", json={
            "host": "example.test",
            "mode": "simulate",
            "ports": "80",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("error", response.get_json()["results"][0])


if __name__ == "__main__":
    unittest.main()
