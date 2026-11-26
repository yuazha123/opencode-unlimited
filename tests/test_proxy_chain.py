import base64
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ouc import proxy_chain


class ProxyStringTests(unittest.TestCase):
    def test_socks5_with_credentials(self):
        spec = proxy_chain.parse_proxy_entry("socks5://user:pass@127.0.0.1:1080")
        self.assertEqual(spec["type"], "socks5")
        self.assertEqual(spec["host"], "127.0.0.1")
        self.assertEqual(spec["port"], 1080)
        self.assertEqual(spec["username"], "user")
        self.assertEqual(spec["password"], "pass")

    def test_relay_url(self):
        spec = proxy_chain.parse_proxy_entry("relay://block:TOKEN@relay.example.com:4443")
        self.assertEqual(spec["type"], "relay")
        self.assertEqual(spec["username"], "block")
        self.assertEqual(spec["password"], "TOKEN")
        self.assertEqual(spec["host"], "relay.example.com")
        self.assertEqual(spec["port"], 4443)

    def test_default_type_and_metadata(self):
        spec = proxy_chain.parse_proxy_entry("proxy.example.com:8080", default_type="http")
        self.assertEqual(spec["type"], "http")
        spec = proxy_chain.parse_proxy_entry("RELAY://h:1")
        self.assertEqual(spec["type"], "relay")

    def test_url_encoded_credentials(self):
        spec = proxy_chain.parse_proxy_entry("socks5://u%40x:p%3Aq@h:1080")
        self.assertEqual(spec["username"], "u@x")
        self.assertEqual(spec["password"], "p:q")

    def test_invalid_entries(self):
        for raw in ("", "nocolon", "host:notint", "host:70000", "host:0", "ftp://h:21"):
            self.assertIsNone(proxy_chain.parse_proxy_entry(raw), raw)

    def test_split_specs(self):
        specs = proxy_chain.parse_proxy_specs("socks5://a:1, http://b:2; relay://c:3")
        self.assertEqual([s["type"] for s in specs], ["socks5", "http", "relay"])
        self.assertEqual(proxy_chain.parse_proxy_list("a:1 b:2"), [("a", 1), ("b", 2)])

    def test_relay_spec_url(self):
        spec = proxy_chain.parse_proxy_entry("relay://block:TOKEN@relay.example.com:4443")
        self.assertEqual(proxy_chain.relay_spec_url(spec), "relay://block:TOKEN@relay.example.com:4443")

    def test_basic_auth_header(self):
        header = proxy_chain.basic_auth_header("u", "p")
        expected = base64.b64encode(b"u:p").decode("ascii")
        self.assertEqual(header, f"Proxy-Authorization: Basic {expected}\r\n")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name in ("EGRESS_CONFIG_FILE", "PROXY_INDEX_FILE", "RELAY_INSECURE_FLAG"):
            patcher = mock.patch.object(proxy_chain, name, root / name)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_defaults(self):
        cfg = proxy_chain.get_egress_config()
        self.assertEqual(cfg["mode"], "warp")
        self.assertEqual(cfg["custom_type"], "socks5")
        self.assertEqual(cfg["custom_proxy"], "127.0.0.1:10808")
        self.assertIn(cfg["warp_scope"], ("tun", "isolated"))

    def test_ring_advances_and_wraps(self):
        proxy_chain.set_egress_config("custom", "socks5://a:1 socks5://b:2", "socks5")
        self.assertEqual(proxy_chain.current_spec()["host"], "a")
        self.assertEqual(proxy_chain.advance_custom_proxy(), 1)
        self.assertEqual(proxy_chain.current_spec()["host"], "b")
        self.assertEqual(proxy_chain.advance_custom_proxy(), 0)
        host, port, index, total = proxy_chain.get_current_custom_proxy()
        self.assertEqual((host, port, index, total), ("a", 1, 0, 2))

    def test_relay_mode_detection(self):
        proxy_chain.set_egress_config("custom", "relay://block:TOKEN@relay.example.com:4443")
        self.assertTrue(proxy_chain.is_relay_mode())
        proxy_chain.set_egress_config("custom", "socks5://a:1")
        self.assertFalse(proxy_chain.is_relay_mode())

    def test_tls_insecurity_is_explicit(self):
        self.assertFalse(proxy_chain.relay_tls_insecure())
        proxy_chain.RELAY_INSECURE_FLAG.write_text("", encoding="utf-8")
        self.assertTrue(proxy_chain.relay_tls_insecure())

    def test_relay_api_request_and_auth_header(self):
        requests = []

        def opener(request, timeout=None, context=None):
            requests.append(request)
            return io.BytesIO(b'{"ok": true, "block": "2606:4700::"}')

        spec = proxy_chain.parse_proxy_entry("relay://block:TOKEN@relay.example.com:4443")
        data = proxy_chain.relay_state(spec, opener=opener)
        self.assertEqual(data["block"], "2606:4700::")
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer TOKEN")
        self.assertEqual(requests[0].full_url, "https://relay.example.com:4443/api/state")

    def test_relay_api_request_failure_is_reported(self):
        def opener(request, timeout=None):
            raise OSError("offline")

        spec = proxy_chain.parse_proxy_entry("relayplain://block:TOKEN@127.0.0.1:4443")
        data = proxy_chain.rotate_relay(spec, opener=opener)
        self.assertFalse(data["ok"])
        self.assertIn("offline", data["error"])


class FakeSocket:
    def __init__(self, response=b""):
        self.sent = bytearray()
        self.response = bytearray(response)
        self.closed = False

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        chunk = bytes(self.response[:size])
        del self.response[:size]
        return chunk

    def close(self):
        self.closed = True


class ConnectTunnelTests(unittest.TestCase):
    def test_http_connect_success(self):
        sock = FakeSocket(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        result = proxy_chain.open_http_proxy_tunnel(
            "api.opencode.ai", 443, "proxy.example.com", 8080,
            username="u", password="p", connect=lambda addr, timeout: sock,
        )
        self.assertIs(result, sock)
        self.assertIn(b"CONNECT api.opencode.ai:443 HTTP/1.1", bytes(sock.sent))
        self.assertIn(b"Proxy-Authorization: Basic", bytes(sock.sent))

    def test_http_connect_refusal_closes_socket(self):
        sock = FakeSocket(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        with self.assertRaises(ConnectionError):
            proxy_chain.open_http_proxy_tunnel(
                "api.opencode.ai", 443, "proxy.example.com", 8080,
                connect=lambda addr, timeout: sock,
            )
        self.assertTrue(sock.closed)


if __name__ == "__main__":
    unittest.main()
