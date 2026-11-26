import asyncio
import base64
import hashlib
import json
import socket
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from relay import blockrelay, warpgate_pool


class HelpersTests(unittest.TestCase):
    def test_hash_token(self):
        self.assertEqual(blockrelay.hash_token("abc"), hashlib.sha256(b"abc").hexdigest())
        self.assertNotIn("abc", blockrelay.hash_token("abc"))

    def test_parse_basic(self):
        header = "Basic " + base64.b64encode(b"block:TOKEN").decode("ascii")
        self.assertEqual(blockrelay.parse_basic(header), "TOKEN")
        self.assertEqual(blockrelay.parse_basic("Basic !!!"), "")
        self.assertEqual(blockrelay.parse_basic("Digest abc"), "")
        self.assertEqual(blockrelay.parse_basic("Bearer TOKEN"), "")

    def test_parse_bearer(self):
        self.assertEqual(blockrelay.parse_bearer("Bearer TOKEN"), "TOKEN")
        self.assertEqual(blockrelay.parse_bearer("TOKEN"), "TOKEN")
        self.assertEqual(blockrelay.parse_bearer(""), "")

    def test_host_allowed(self):
        self.assertTrue(blockrelay.host_allowed("anything.example", ["*"]))
        self.assertTrue(blockrelay.host_allowed("api.opencode.ai", ["opencode.ai"]))
        self.assertTrue(blockrelay.host_allowed("OPENCODE.AI.", ["opencode.ai"]))
        self.assertFalse(blockrelay.host_allowed("evil.com", ["opencode.ai"]))

    def test_block_of(self):
        self.assertEqual(blockrelay.block_of("2606:4700:1:2::9"), "2606:4700:1:2::")
        self.assertEqual(blockrelay.block_of("1.2.3.4"), "1.2.3.4")

    def test_utc_midnight(self):
        noon = datetime(2026, 11, 25, 12, tzinfo=timezone.utc).timestamp()
        self.assertEqual(blockrelay.utc_midnight(noon), int(datetime(2026, 11, 26, tzinfo=timezone.utc).timestamp()))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write_config(self, **overrides):
        data = {
            "listen": "127.0.0.1", "port": 4443,
            "database": str(self.root / "relay.db"),
            "prefixes": ["2001:db8:1234::/48"],
            "admin_token": "admin-token", "enroll_secret": "enroll-secret",
            "tls": {"cert": "", "key": ""},
            "upstream": {"mode": "prefix", "warpgate": {"url": ""}},
        }
        data.update(overrides)
        path = self.root / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_valid_prefix_config(self):
        cfg = blockrelay.Config.load(self.write_config())
        self.assertEqual(cfg.listen, "127.0.0.1")
        self.assertEqual(cfg.upstream_mode, "prefix")
        self.assertEqual(cfg.capacity, 65536)
        self.assertTrue(cfg.uses_prefix)
        self.assertFalse(cfg.uses_warpgate)

    def test_invalid_mode_rejected(self):
        path = self.write_config(upstream={"mode": "anything", "warpgate": {"url": ""}})
        with self.assertRaises(ValueError):
            blockrelay.Config.load(path)

    def test_public_listener_requires_tls(self):
        path = self.write_config(listen="0.0.0.0")
        with self.assertRaises(ValueError):
            blockrelay.Config.load(path)

    def test_missing_admin_token_rejected(self):
        with self.assertRaises(ValueError):
            blockrelay.Config.load(self.write_config(admin_token=""))

    def test_warpgate_mode_requires_url(self):
        path = self.write_config(upstream={"mode": "warpgate", "warpgate": {"url": ""}})
        with self.assertRaises(ValueError):
            blockrelay.Config.load(path)

    def test_warpgate_mode_builds_pool(self):
        path = self.write_config(upstream={
            "mode": "warpgate",
            "warpgate": {"url": "http://127.0.0.1:4433", "username": "u", "password": "p", "verify_tls": False},
        })
        cfg = blockrelay.Config.load(path)
        self.assertIsNotNone(cfg.pool())
        self.assertTrue(cfg.uses_warpgate)

    def test_config_example_has_placeholders(self):
        cfg = blockrelay.Config.load(Path(__file__).resolve().parents[1] / "relay" / "config.example.json")
        self.assertIn("CHANGE-ME", cfg.admin_token)
        self.assertIn("CHANGE-ME", cfg.enroll_secret)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.store = blockrelay.Store(":memory:")

    def test_client_token_is_hashed_and_lookup_works(self):
        cid, token, _ = self.store.create_client("admin", "laptop")
        row = self.store.client_by_token(token)
        self.assertEqual(row["id"], cid)
        hashes = [r["token_hash"] for r in self.store.list_clients()]
        self.assertNotIn(token, hashes)
        self.assertIn(blockrelay.hash_token(token), hashes)
        self.assertIsNone(self.store.client_by_token("wrong-token"))

    def test_assign_burn_and_revoke(self):
        cid, token, _ = self.store.create_client("admin", "laptop")
        self.store.assign(cid, "2606:4700::", "prefix")
        self.assertEqual(self.store.client_by_id(cid)["block"], "2606:4700::")
        self.store.mark_burnt("2606:4700::")
        self.assertIn("2606:4700::", self.store.used_blocks())
        self.assertTrue(self.store.revoke(cid))
        self.assertIsNone(self.store.client_by_token(token))
        self.assertFalse(self.store.revoke("missing"))

    def test_settings_round_trip(self):
        self.store.set_setting("epoch", "7")
        self.assertEqual(self.store.get_setting("epoch"), "7")
        self.assertEqual(self.store.get_setting("missing", "default"), "default")


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.cfg = blockrelay.Config(prefixes=["2001:db8:1234::/48"], admin_token="x", listen="127.0.0.1")
        self.store = blockrelay.Store(":memory:")
        self.cid, self.token, _ = self.store.create_client("x", "test")

    def test_prefix_blocks_are_64_and_sticky(self):
        router = blockrelay.Router(self.cfg, self.store)
        route = router.ensure(self.store.client_by_id(self.cid))
        self.assertEqual(route.block, "2001:db8:1234::")
        self.assertEqual(route.lane, "prefix")
        again = router.ensure(self.store.client_by_id(self.cid))
        self.assertEqual(again.block, route.block)

    def test_rotate_burns_old_block(self):
        router = blockrelay.Router(self.cfg, self.store)
        router.ensure(self.store.client_by_id(self.cid))
        rotated = router.rotate(self.store.client_by_id(self.cid))
        self.assertEqual(rotated.block, "2001:db8:1234:1::")
        self.assertIn("2001:db8:1234::", self.store.used_blocks())

    def test_exhausted_prefix_raises(self):
        cfg = blockrelay.Config(prefixes=["2001:db8:1234::/64"], admin_token="x", listen="127.0.0.1")
        store = blockrelay.Store(":memory:")
        cid, _, _ = store.create_client("x", "one")
        router = blockrelay.Router(cfg, store)
        router.ensure(store.client_by_id(cid))
        other, _, _ = store.create_client("x", "two")
        with self.assertRaises(blockrelay.NoCapacity):
            router.ensure(store.client_by_id(other))

    def test_warpgate_route_uses_injected_probe(self):
        cfg = blockrelay.Config(admin_token="x", listen="127.0.0.1", upstream_mode="warpgate")
        store = blockrelay.Store(":memory:")
        cid, _, _ = store.create_client("x", "gate")
        pool = mock.Mock()
        pool.acquire.return_value = warpgate_pool.Instance(
            name="warp-1", host="127.0.0.1", port=1080, advertised_ip="2606:4700:abcd::1"
        )
        router = blockrelay.Router(cfg, store, pool=pool, probe=lambda instance: "2606:4700:abcd::1")
        route = router.ensure(store.client_by_id(cid))
        self.assertEqual(route.block, "2606:4700:abcd::")
        self.assertEqual(route.lane, "warpgate")
        self.assertEqual(route.exit_ip, "2606:4700:abcd::1")
        pool.acquire.assert_called_once()

    def test_open_connection_uses_injected_dialer(self):
        local, remote = socket.socketpair()

        def dial(host, port, route):
            return local

        async def run():
            reader, writer = await asyncio.wait_for(self.router.open_connection("x", 443, self.route), 2)
            remote.sendall(b"ok")
            data = await asyncio.wait_for(reader.read(10), 2)
            writer.close()
            return data

        router = blockrelay.Router(self.cfg, self.store, dial=dial)
        self.route = blockrelay.Route("2001:db8:1234::", "prefix")
        self.router = router
        self.assertEqual(asyncio.run(run()), b"ok")
        remote.close()


class WarpGateTests(unittest.TestCase):
    def test_split_credentials_and_index(self):
        user, pw, clean = warpgate_pool.split_credentials("http://u:p@10.0.0.5:4433")
        self.assertEqual((user, pw, clean), ("u", "p", "http://10.0.0.5:4433"))
        self.assertEqual(warpgate_pool.index_from_name("warp-12"), 12)
        self.assertIsNone(warpgate_pool.index_from_name("other"))

    def test_pool_with_injected_control_plane(self):
        def request(method, path, payload=None):
            if path == "/api/instances":
                return {"code": "00000", "data": {"instances": [
                    {"name": "warp-1", "host": "10.0.0.1", "port": 1080, "status": "idle", "ip": "2606:4700::1"},
                    {"name": "warp-2", "host": "10.0.0.2", "port": 1080, "status": "busy"},
                ]}}
            if path == "/api/acquire":
                return {"code": "00000", "data": {
                    "name": "warp-1", "host": "10.0.0.1", "port": 1080,
                    "username": "u", "password": "p", "ip": "2606:4700::1",
                }}
            if path == "/api/release":
                return {"code": "00000"}
            raise AssertionError(path)

        pool = warpgate_pool.WarpGatePool("http://10.0.0.5:4433", request=request)
        stats = pool.stats()
        self.assertEqual((stats.instances, stats.available, stats.in_use), (2, 1, 1))
        self.assertEqual(len(pool.instances()), 2)
        instance = pool.acquire("client-1")
        self.assertEqual(instance.endpoint, "10.0.0.1:1080")
        self.assertIn("socks5h://u:p@", instance.proxy_url)
        self.assertIsNone(pool.release("warp-1"))

    def test_socks5_handshake_with_scripted_socket(self):
        class ScriptedSocket:
            def __init__(self):
                self.sent = []
                self.responses = [
                    b"\x05\x02",
                    b"\x01\x00",
                    b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") + (80).to_bytes(2, "big"),
                ]
                self.closed = False

            def sendall(self, data):
                self.sent.append(data)

            def recv(self, size):
                return self.responses.pop(0) if self.responses else b""

            def close(self):
                self.closed = True

        sock = ScriptedSocket()
        result = warpgate_pool.socks5_connect(
            "1.2.3.4", 80, "proxy.example", 1080, "u", "p",
            connect=lambda addr, timeout: sock,
        )
        self.assertIs(result, sock)
        self.assertEqual(sock.sent[0], b"\x05\x01\x02")
        self.assertIn(b"\x01\x01u\x01p", sock.sent[1])
        self.assertEqual(sock.sent[2][:4], b"\x05\x01\x00\x01")

    def test_socks5_refusal_closes_socket(self):
        class RefusedSocket:
            def __init__(self):
                self.closed = False

            def sendall(self, data):
                pass

            def recv(self, size):
                return b"\x05\xff"

            def close(self):
                self.closed = True

        sock = RefusedSocket()
        with self.assertRaises(ConnectionError):
            warpgate_pool.socks5_connect("h", 80, "p", 1080, connect=lambda a, timeout: sock)
        self.assertTrue(sock.closed)


if __name__ == "__main__":
    unittest.main()
