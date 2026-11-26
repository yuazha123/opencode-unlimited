import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ouc import auto_resume


class FlagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(auto_resume, "AUTO_RESUME_FLAG", Path(self.tmp.name) / "auto_resume.flag")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_disabled_by_default(self):
        self.assertFalse(auto_resume.is_auto_resume_enabled())
        self.assertEqual(auto_resume.resume_sessions(["ses_1"]), [])

    def test_explicit_toggle(self):
        auto_resume.set_auto_resume(True)
        self.assertTrue(auto_resume.is_auto_resume_enabled())
        auto_resume.set_auto_resume(False)
        self.assertFalse(auto_resume.is_auto_resume_enabled())

    def test_session_id_extraction(self):
        self.assertEqual(auto_resume.session_id_in("wall sessionID=ses_abc123 detail"), "ses_abc123")
        self.assertEqual(auto_resume.session_id_in("no id here"), "")

    def test_resume_dispatch(self):
        auto_resume.set_auto_resume(True)
        calls = []

        def runner(args):
            calls.append(args)
            return True

        self.assertEqual(auto_resume.resume_sessions(["ses_1", "ses_2"], runner=runner), ["ses_1", "ses_2"])
        self.assertEqual(calls[0], ["opencode", "run", "--session", "ses_1", "continue"])

    def test_failed_dispatch_is_not_reported(self):
        auto_resume.set_auto_resume(True)
        self.assertEqual(auto_resume.resume_sessions(["ses_1"], runner=lambda args: False), [])


class LockoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "drafts.sqlite"
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE state(key TEXT PRIMARY KEY, value TEXT)")
        conn.executemany(
            "INSERT INTO state(key,value) VALUES(?,?)",
            [("free-limit", "1"), ("go-upsell", "1"), ("quota_exceeded", "1"), ("keep-me", "hello")],
        )
        conn.commit()
        conn.close()
        patcher = mock.patch.object(auto_resume, "draft_db_candidates", lambda: [self.db])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_clear_only_known_lockout_keys(self):
        self.assertEqual(auto_resume.clear_lockouts(), 3)
        conn = sqlite3.connect(self.db)
        rows = dict(conn.execute("SELECT key,value FROM state").fetchall())
        conn.close()
        self.assertEqual(rows, {"keep-me": "hello"})

    def test_clear_is_idempotent(self):
        self.assertEqual(auto_resume.clear_lockouts(), 3)
        self.assertEqual(auto_resume.clear_lockouts(), 0)

    def test_latest_session_reads_only(self):
        db = Path(self.tmp.name) / "opencode.db"
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE session_v2(id TEXT, directory TEXT, title TEXT, time_updated INTEGER, time_archived INTEGER)"
        )
        conn.execute("INSERT INTO session_v2 VALUES('ses_7','/tmp','Title',10,NULL)")
        conn.execute("INSERT INTO session_v2 VALUES('ses_6','/tmp','Old',5,NULL)")
        conn.commit()
        conn.close()
        self.assertEqual(auto_resume.latest_session(db), ("ses_7", "/tmp", "Title"))


if __name__ == "__main__":
    unittest.main()
