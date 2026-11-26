import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ouc import auto_resume, common, workers


class WallDetectionTests(unittest.TestCase):
    def test_wall_patterns(self):
        for line in (
            "Free limit reached for this account",
            "free usage exceeded",
            "rate limit hit",
            "quota_exceeded: 0 remaining",
            "HTTP 403: free tier error",
        ):
            self.assertTrue(workers.is_wall(line), line)
        for line in ("all good", "response streamed", "connected to api.opencode.ai"):
            self.assertFalse(workers.is_wall(line), line)

    def test_read_new_log_from_offset(self):
        first = "ok line\nfree limit reached sessionID=ses_123\n"
        wall, sessions, offset = workers.read_new_log(first, 0)
        self.assertTrue(wall)
        self.assertEqual(sessions, ["ses_123"])
        self.assertEqual(offset, len(first))

        wall, sessions, offset = workers.read_new_log(first, offset)
        self.assertFalse(wall)
        self.assertEqual(sessions, [])
        self.assertEqual(offset, len(first))


class BackoffTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000

    def test_blacklist_is_per_utc_day(self):
        state = workers.default_state()
        workers.mark_burnt(state, "2606:4700::", now=self.now)
        self.assertTrue(workers.is_burnt(state, "2606:4700::", now=self.now))
        workers.prune_blacklist(state, now=self.now + 86401)
        self.assertFalse(workers.is_burnt(state, "2606:4700::", now=self.now + 86401))

    def test_pause_after_two_confirmed_blocks(self):
        state = workers.default_state()
        workers.mark_burnt(state, "2606:4700::", now=self.now)
        workers.mark_burnt(state, "2606:4700:1::", now=self.now)
        reason = workers.note_wall(state, ["2606:4700::", "2606:4700:1::"], now=self.now)
        self.assertEqual(reason, "allowance window")
        self.assertEqual(state["paused_until"], common.next_utc_midnight(self.now))

    def test_single_confirmed_block_does_not_pause(self):
        state = workers.default_state()
        workers.mark_burnt(state, "2606:4700::", now=self.now)
        self.assertEqual(workers.note_wall(state, ["2606:4700::"], now=self.now), "")
        self.assertEqual(workers.pause_left(state, now=self.now), 0)

    def test_rotation_holds(self):
        state = workers.default_state()
        self.assertEqual(workers.rotation_blocked(state, now=self.now), "")
        self.assertEqual(workers.rotation_blocked(state, streaming=True, now=self.now), "response is streaming")
        state["last_hop"] = self.now - 10
        self.assertEqual(workers.rotation_blocked(state, now=self.now), "rotation cooldown")
        state["paused_until"] = self.now + 600
        self.assertEqual(workers.rotation_blocked(state, now=self.now), "paused until allowance window")


class TickTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for module, name in (
            (workers, "GUARD_HEARTBEAT"), (workers, "KEEPER_HEARTBEAT"),
            (common, "GUARD_STATE_FILE"), (common, "GUARD_LOG_FILE"),
            (auto_resume, "AUTO_RESUME_FLAG"),
        ):
            patcher = mock.patch.object(module, name, root / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.probe = mock.patch.object(common, "probe_egress", lambda: "1.2.3.4")
        self.probe.start()
        self.addCleanup(self.probe.stop)

    def test_guard_quiet_log(self):
        result = workers.guard_tick(log_text="all good\n", state=workers.default_state())
        self.assertEqual(result["action"], "none")
        self.assertFalse(result["wall"])
        self.assertIsNotNone(common.heartbeat_age(workers.GUARD_HEARTBEAT))
        self.assertEqual(common.read_json(common.GUARD_STATE_FILE, {})["log_offset"], len("all good\n"))

    def test_guard_rotates_on_wall(self):
        result = workers.guard_tick(
            log_text="free limit reached\n",
            rotator=lambda: (True, "2606:4700::"),
            state=workers.default_state(),
        )
        self.assertEqual(result["action"], "rotated")
        self.assertTrue(result["wall"])

    def test_guard_holds_while_streaming(self):
        result = workers.guard_tick(
            log_text="free limit reached\n",
            rotator=lambda: (_ for _ in ()).throw(AssertionError("must not rotate")),
            stream_probe=lambda: True,
            state=workers.default_state(),
        )
        self.assertTrue(result["action"].startswith("hold:"))

    def test_guard_cooldown(self):
        state = workers.default_state()
        state["last_hop"] = time.time() - 10
        result = workers.guard_tick(log_text="quota exceeded\n", rotator=lambda: (True, "x"), state=state)
        self.assertTrue(result["action"].startswith("hold:"))

    def test_keeper_ticks(self):
        self.assertEqual(workers.keeper_tick(connected=True)["action"], "healthy")
        self.assertEqual(workers.keeper_tick(connected=False, repair=lambda: True)["action"], "repaired")
        self.assertEqual(workers.keeper_tick(connected=False, repair=lambda: False)["action"], "repair failed")
        self.assertIsNotNone(common.heartbeat_age(workers.KEEPER_HEARTBEAT))

    def test_watchdog(self):
        self.assertEqual(workers.watchdog_check("unknown"), "unknown worker")
        self.assertEqual(workers.watchdog_check("guard"), "restart unavailable")
        called = []
        self.assertEqual(
            workers.watchdog_check("guard", start=lambda: called.append(1) or True), "restarted"
        )
        self.assertEqual(len(called), 1)
        common.heartbeat(workers.GUARD_HEARTBEAT)
        self.assertEqual(workers.watchdog_check("guard"), "alive")


if __name__ == "__main__":
    unittest.main()
