import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ouc import desktop_brand

JS = (
    '"dialog.usageExceeded.freeTier.title":`Free limit reached`\n'
    '"dialog.usageExceeded.freeTier.description":`Subscribe to OpenCode Go for reliable access '
    "to the best open-source models for $10/month.`\n"
    '"dialog.usageExceeded.freeTier.actionLabel":`Subscribe`\n'
)
HTML = "<html><head><title>OpenCode</title></head><body>unchanged body</body></html>"


def make_archive(path: Path) -> bytes:
    js_b = JS.encode("utf-8")
    html_b = HTML.encode("utf-8")
    header = {"files": {"out": {"files": {"renderer": {"files": {
        "main-abc.js": {
            "offset": "0", "size": str(len(js_b)),
            "integrity": {"algorithm": "SHA256", "hash": hashlib.sha256(js_b).hexdigest(), "blockSize": 4194304},
        },
        "index.html": {"offset": str(len(js_b)), "size": str(len(html_b))},
    }}}}}}
    data = desktop_brand.prelude_bytes(header) + js_b + html_b
    path.write_bytes(data)
    return data


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for name in ("STATE_DIR", "HEADER_COPY", "INTENT_FILE", "BRAND_LOG_FILE"):
            patcher = mock.patch.object(desktop_brand, name, root / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.archive = root / "app.asar"
        self.original = make_archive(self.archive)

    def test_status_reports_candidates_without_changing_file(self):
        report = desktop_brand.status(self.archive)
        self.assertTrue(report["exists"])
        self.assertFalse(report["patched"])
        self.assertEqual(report["blockers"], [])
        self.assertEqual(len(report["would_change"]), 4)
        self.assertEqual(self.archive.read_bytes(), self.original)

    def test_dry_run_is_default(self):
        report = desktop_brand.apply(self.archive)
        self.assertTrue(report["dry_run"])
        self.assertEqual(self.archive.read_bytes(), self.original)

    def test_apply_preserves_untouched_entries_and_updates_integrity(self):
        report = desktop_brand.apply(self.archive, apply_change=True)
        self.assertIn("out/renderer/main-abc.js", report["applied"])
        self.assertIn("out/renderer/index.html", report["applied"])

        with self.archive.open("rb") as handle:
            header, start, _ = desktop_brand.archive_header(handle)
            js = desktop_brand.entry_bytes(handle, start, desktop_brand.node_at(header, ("out", "renderer", "main-abc.js")))
            html = desktop_brand.entry_bytes(handle, start, desktop_brand.node_at(header, ("out", "renderer", "index.html")))
        self.assertIn("Free allowance used up", js.decode("utf-8"))
        self.assertIn("Pricing", js.decode("utf-8"))
        self.assertIn("<title>Opencode Unlimited</title>", html.decode("utf-8"))
        self.assertIn("unchanged body", html.decode("utf-8"))

        integrity = desktop_brand.node_at(header, ("out", "renderer", "main-abc.js"))["integrity"]
        self.assertEqual(integrity["hash"], hashlib.sha256(js).hexdigest())

    def test_restore_returns_original_bytes(self):
        desktop_brand.apply(self.archive, apply_change=True)
        report = desktop_brand.restore(self.archive)
        self.assertTrue(report["ok"])
        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertFalse(desktop_brand.HEADER_COPY.exists())

    def test_apply_refuses_while_app_is_open(self):
        report = desktop_brand.apply(self.archive, apply_change=True, app_open=True)
        self.assertIn("app is running", report["blockers"])
        self.assertEqual(self.archive.read_bytes(), self.original)

    def test_status_on_missing_archive(self):
        report = desktop_brand.status(self.archive.parent / "missing.asar")
        self.assertFalse(report["exists"])
        self.assertIn("archive not found", report["blockers"])

    def test_restore_without_saved_header_fails(self):
        report = desktop_brand.restore(self.archive)
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()
