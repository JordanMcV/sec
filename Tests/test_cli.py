import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="sec-tests-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / "sec"
        subprocess.run([
            "swiftc", "-warnings-as-errors", "-module-cache-path",
            os.environ.get("SWIFT_MODULE_CACHE_PATH", str(Path(cls.directory.name) / "module-cache")),
            str(ROOT / "Sources/main.swift"), str(ROOT / "Tests/KeychainStub.swift"),
            "-framework", "LocalAuthentication", "-framework", "Security",
            "-o", str(cls.binary),
        ], check=True)

    def run_cli(self, *args, items=None, data=None, extra=None):
        env = dict(os.environ)
        for name in list(env):
            if name.startswith("TEST_"):
                del env[name]
        env["SEC_SKIP_BIOMETRY"] = "1"
        env["TEST_ITEMS"] = json.dumps({
            name: base64.b64encode(value).decode() for name, value in (items or {}).items()
        })
        env.update(extra or {})
        return subprocess.run([str(self.binary), *args], input=data,
                              capture_output=True, env=env, timeout=10)

    def test_replacement_updates_without_delete(self):
        result = self.run_cli("set", "key", items={"key": b"old"}, data=b"new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"TEST updated key=bmV3", result.stderr)
        self.assertNotIn(b"TEST deleted", result.stderr)

    def test_failed_update_preserves_old_value(self):
        result = self.run_cli("set", "key", items={"key": b"old"}, data=b"new",
                              extra={"TEST_FAIL_UPDATE": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"TEST update-failed key=b2xk", result.stderr)
        self.assertNotIn(b"TEST deleted", result.stderr)
        self.assertNotIn(b"TEST added", result.stderr)

    def test_new_secret_is_added(self):
        result = self.run_cli("set", "key", data=b"new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"TEST added key=bmV3", result.stderr)

    def test_failed_add_reports_error(self):
        result = self.run_cli("set", "key", data=b"new", extra={"TEST_FAIL_ADD": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"stored 'key'", result.stderr)

    def test_concurrent_add_is_updated(self):
        result = self.run_cli("set", "key", data=b"new", extra={"TEST_ADD_RACE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"TEST updated key=bmV3", result.stderr)
        self.assertNotIn(b"TEST deleted", result.stderr)


if __name__ == "__main__":
    unittest.main()
