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

    def test_invalid_values_are_rejected_before_storage(self):
        for value in (b"\xff", b"first\0second", b"\0first", b"first\0"):
            with self.subTest(value=value):
                result = self.run_cli("set", "key", items={"key": b"old"}, data=value)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(b"TEST ", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_invalid_stored_values_do_not_run_command(self):
        for value in (b"\xff", b"first\0second", b"\0first", b"first\0"):
            with self.subTest(value=value):
                result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed",
                                      items={"key": value})
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")

    def test_unicode_and_multiline_values_are_preserved(self):
        value = "caf\u00e9\nsecond line".encode()
        stored = self.run_cli("set", "key", data=value)
        self.assertEqual(stored.returncode, 0, stored.stderr)
        self.assertIn(base64.b64encode(value), stored.stderr)
        result = self.run_cli("run", "key", "--", "/bin/sh", "-c", 'printf "%s" "$KEY"',
                              items={"key": value})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, value)

    def test_invalid_mappings_fail_before_authentication(self):
        for spec in ("", "=key", "TOKEN=", "BAD-NAME=key", "1key", "caf\u00e9", "TOKEN\n=key"):
            with self.subTest(spec=spec):
                result = self.run_cli("run", spec, "--", "/usr/bin/printf", "executed")
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(b"skipping Touch ID", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_duplicate_variables_fail_before_authentication(self):
        for specs in (("api-key", "api_key"), ("TOKEN=first", "TOKEN=second"), ("key", "KEY=key")):
            with self.subTest(specs=specs):
                result = self.run_cli("run", *specs, "--", "/usr/bin/printf", "executed")
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"duplicate environment variable", result.stderr)
                self.assertNotIn(b"skipping Touch ID", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_explicit_aliases_support_arbitrary_nonempty_secret_names(self):
        result = self.run_cli("run", "FIRST=1key", "_second2=caf\u00e9", "THIRD==key", "--",
                              "/bin/sh", "-c", 'printf "%s:%s:%s" "$FIRST" "$_second2" "$THIRD"',
                              items={"1key": b"one", "caf\u00e9": b"two", "=key": b"three"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"one:two:three")

    def test_empty_secret_name_is_not_stored(self):
        result = self.run_cli("set", "", data=b"value")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST ", result.stderr)

    def test_failed_environment_update_does_not_run_command(self):
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed",
                              items={"key": b"value"}, extra={"TEST_FAIL_SETENV": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"could not set environment variable 'KEY'", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_list_marks_names_that_need_an_alias(self):
        result = self.run_cli("list", items={"1key": b"one", "key": b"two"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"1key\t(use VAR=name)\nkey\t$KEY\n")


if __name__ == "__main__":
    unittest.main()
