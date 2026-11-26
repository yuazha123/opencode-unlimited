import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from ouc import zen_proxy


class HealthTrailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name in ("PROXY_STATUS_FILE", "PROXY_LOG_FILE", "FALLBACK_FLAG"):
            patcher = mock.patch.object(zen_proxy, name, root / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        zen_proxy._ACTIVE_TUNNELS = 0

    def test_events_and_error_tracking(self):
        zen_proxy.record_event("start", "listening", host="127.0.0.1")
        event = zen_proxy.record_event("reset", "peer closed", host="api.opencode.ai")
        status = zen_proxy.read_status()
        self.assertEqual(status["last_event"], event)
        self.assertEqual(status["last_error"], "peer closed")
        self.assertEqual(status["last_error_ts"], event["ts"])

    def test_event_ring_is_bounded_and_recent(self):
        for i in range(40):
            zen_proxy.record_event("hold", f"event {i}")
        status = zen_proxy.read_status()
        self.assertEqual(len(status["recent"]), 30)
        self.assertEqual(status["recent"][-1]["detail"], "event 39")

    def test_special_event_fields(self):
        zen_proxy.record_event("fallback", "direct route")
        zen_proxy.record_event("edge_fail", "bad edge", edge="1.1.1.1")
        status = zen_proxy.read_status()
        self.assertGreater(status["fallback_ts"], 0)
        self.assertEqual(status["last_bad_edge"], "1.1.1.1")
        self.assertEqual(status["edge"], "1.1.1.1")
        self.assertTrue(zen_proxy.FALLBACK_FLAG.parent.is_dir())

    def test_tunnel_counting(self):
        with zen_proxy.tunnel():
            self.assertEqual(zen_proxy.active_tunnels(), 1)
            with zen_proxy.tunnel():
                self.assertEqual(zen_proxy.active_tunnels(), 2)
            self.assertEqual(zen_proxy.active_tunnels(), 1)
        self.assertEqual(zen_proxy.active_tunnels(), 0)
        self.assertEqual(zen_proxy.proxy_status()["tunnels"], 0)


class ByteRelayTests(unittest.TestCase):
    def test_relays_bytes_and_reports_clean_end(self):
        client, upstream = socket.socketpair()
        result = {}

        def run():
            result["outcome"] = zen_proxy.relay_bytes(client, upstream)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        upstream.settimeout(3)
        client.sendall(b"hello")
        self.assertEqual(upstream.recv(100), b"hello")
        client.shutdown(socket.SHUT_WR)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["outcome"], "")


class ProxyServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name in ("PROXY_STATUS_FILE", "PROXY_LOG_FILE", "FALLBACK_FLAG"):
            patcher = mock.patch.object(zen_proxy, name, root / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        zen_proxy._ACTIVE_TUNNELS = 0

    def test_connect_handshake_and_payload(self):
        pairs = []

        def opener(host, port):
            local, remote = socket.socketpair()
            pairs.append((host, port, local, remote))
            return local

        server, port = zen_proxy.start_proxy_server("127.0.0.1", 0, open_upstream=opener)
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.settimeout(3)
            client.sendall(b"CONNECT api.opencode.ai:443 HTTP/1.1\r\nHost: api.opencode.ai:443\r\n\r\n")
            head = b""
            while b"\r\n\r\n" not in head:
                head += client.recv(1024)
            self.assertIn(b"200 Connection Established", head)

            client.sendall(b"ping")
            remote = pairs[0][3]
            remote.settimeout(3)
            self.assertEqual(remote.recv(100), b"ping")
            remote.close()
            client.close()
            deadline = time.time() + 3
            while time.time() < deadline and zen_proxy.active_tunnels():
                time.sleep(0.02)
            self.assertEqual(zen_proxy.active_tunnels(), 0)
            self.assertEqual(pairs[0][0], "api.opencode.ai")
            self.assertEqual(pairs[0][1], 443)
            kinds = [e["kind"] for e in zen_proxy.read_status().get("recent", [])]
            self.assertIn("start", kinds)
            self.assertIn("hold", kinds)
        finally:
            zen_proxy.stop_proxy(server)

    def test_bad_request_is_rejected(self):
        server, port = zen_proxy.start_proxy_server(
            "127.0.0.1", 0, open_upstream=lambda host, p: (_ for _ in ()).throw(AssertionError("must not dial"))
        )
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.settimeout(3)
            client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertIn(b"405", client.recv(1024))
            client.close()
        finally:
            zen_proxy.stop_proxy(server)


if __name__ == "__main__":
    unittest.main()
