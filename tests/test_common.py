import io
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from ouc import common


class ParseAddressTests(unittest.TestCase):
    def test_normalize_v6_64(self):
        self.assertEqual(common.normalize_v6_64("2606:4700:1234:5678::1"), "2606:4700:1234:5678::")
        self.assertEqual(common.normalize_v6_64("2606:4700:aaaa::99"), "2606:4700:aaaa::")
        self.assertEqual(common.normalize_v6_64("::1"), "")
        self.assertEqual(common.normalize_v6_64("fe80::1%eth0"), "")
        self.assertEqual(common.normalize_v6_64("fd00::1"), "")
        self.assertEqual(common.normalize_v6_64("not-an-ip"), "")

    def test_block_of(self):
        self.assertEqual(common.block_of("2606:4700:1234:5678::1"), "2606:4700:1234:5678::")
        self.assertEqual(common.block_of("1.2.3.4"), "1.2.3.4")
        self.assertEqual(common.block_of("10.0.0.1"), "10.0.0.1")
        self.assertEqual(common.block_of("garbage"), "")

    def test_parse_egress_body(self):
        self.assertEqual(common.parse_egress_body("ip=1.2.3.4\nfl=123\n"), "1.2.3.4")
        self.assertEqual(common.parse_egress_body("2606:4700::9"), "2606:4700::9")
        self.assertEqual(common.parse_egress_body("ip=10.0.0.1\n"), "")
        self.assertEqual(common.parse_egress_body(""), "")

    def test_probe_egress_tries_endpoints_in_order(self):
        seen = []

        def opener(url, timeout=None):
            seen.append(url)
            if "bad" in url:
                raise OSError("offline")
            return io.BytesIO(b"ip=1.2.3.4\n")

        found = common.probe_egress(endpoints=("https://bad", "https://good"), opener=opener)
        self.assertEqual(found, "1.2.3.4")
        self.assertEqual(seen, ["https://bad", "https://good"])

    def test_probe_egress_all_fail(self):
        def opener(url, timeout=None):
            raise OSError("offline")

        self.assertEqual(common.probe_egress(endpoints=("a",), opener=opener), "")

    def test_is_cloudflare_v6(self):
        self.assertTrue(common.is_cloudflare_v6("2606:4700:1234::1"))
        self.assertTrue(common.is_cloudflare_v6("2a09:bac0::1"))
        self.assertFalse(common.is_cloudflare_v6("2001:4860::1"))
        self.assertFalse(common.is_cloudflare_v6("1.2.3.4"))

    def test_utc_helpers(self):
        noon = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc).timestamp()
        midnight = datetime(2026, 11, 26, 0, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(common.next_utc_midnight(noon), int(midnight))
        self.assertEqual(common.utc_day(noon), int(noon) // 86400)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_json_round_trip_and_atomic_write(self):
        path = self.root / "nested" / "state.json"
        common.write_json(path, {"a": 1, "b": [2, 3]}, indent=2)
        self.assertEqual(common.read_json(path, {}), {"a": 1, "b": [2, 3]})
        self.assertFalse((self.root / "nested" / "state.json.tmp").exists())

    def test_read_json_default_on_bad_input(self):
        path = self.root / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        self.assertEqual(common.read_json(path, {"fallback": True}), {"fallback": True})
        self.assertEqual(common.read_json(self.root / "missing.json", 7), 7)

    def test_heartbeat(self):
        path = self.root / "worker" / "heartbeat"
        self.assertIsNone(common.heartbeat_age(path))
        common.heartbeat(path)
        age = common.heartbeat_age(path)
        self.assertIsNotNone(age)
        self.assertLess(age, 5)

    def test_append_log_rotates(self):
        path = self.root / "guard.log"
        for _ in range(5):
            common.append_log(path, "line", limit_bytes=1)
        self.assertTrue(path.is_file())
        self.assertTrue(path.with_suffix(".log.1").is_file())
        self.assertIn("line", path.read_text(encoding="utf-8"))

    def test_service_proxy_wiring(self):
        path = self.root / "service.json"
        path.write_text('{"env":{"HTTPS_PROXY":"http://127.0.0.1:41987"}}', encoding="utf-8")
        with mock.patch.object(common, "SERVICE_FILE", path):
            self.assertTrue(common.service_proxy_wired(41987))
            self.assertFalse(common.service_proxy_wired(9999))
        path.write_text('{"env":null}', encoding="utf-8")
        with mock.patch.object(common, "SERVICE_FILE", path):
            self.assertFalse(common.service_proxy_wired(41987))

    def test_run_uses_argument_list(self):
        result = common.run([common.sys.executable, "-c", "print('ok')"], timeout=5)
        self.assertIsNotNone(result)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
