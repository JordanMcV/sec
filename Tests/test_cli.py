import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
KEYS = "sec.enclave-key.v1"
SECRETS = "sec.encrypted.v1"


def b64(value):
    return base64.b64encode(value).decode()


class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="sec-tests-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / "sec"
        sources = sorted(str(p) for p in (ROOT / "Sources").glob("*.swift") if p.name != "Enclave.swift")
        subprocess.run([
            "swiftc", "-target", f"{os.uname().machine}-apple-macos14.0", "-warnings-as-errors", "-module-cache-path",
            os.environ.get("SWIFT_MODULE_CACHE_PATH", str(Path(cls.directory.name) / "module-cache")),
            *sources, str(ROOT / "Tests/KeychainStub.swift"), str(ROOT / "Tests/VaultKeyStub.swift"),
            "-framework", "CryptoKit", "-framework", "Security", "-o", str(cls.binary),
        ], check=True, env={**os.environ, "MACOSX_DEPLOYMENT_TARGET": "14.0"})

    def setUp(self):
        self.state_path = Path(self.directory.name) / "state.json"
        self.save({KEYS: {"default": b64(bytes([1]) * 32)}})

    def save(self, state):
        self.state_path.write_text(json.dumps(state))

    def state(self):
        return json.loads(self.state_path.read_text())

    def run_cli(self, *args, items=None, data=None, extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("TEST_")}
        env["TEST_STATE"] = str(self.state_path)
        # Setting the former bypass must not affect authentication enforcement.
        env["SEC_SKIP_BIOMETRY"] = "1"
        if items is not None:
            env["TEST_FIXTURES"] = json.dumps({name: b64(value) for name, value in items.items()})
        env.update(extra or {})
        return subprocess.run([str(self.binary), *args], input=data, capture_output=True, env=env, timeout=10)

    def assert_runs_value(self, name, value):
        result = self.run_cli("run", f"VALUE={name}", "--", "/bin/sh", "-c", 'printf "%s" "$VALUE"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, value)

    def test_init_generates_persists_and_verifies_key(self):
        self.save({})
        result = self.run_cli("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"TEST authenticated", result.stderr)
        self.assertIn("default", self.state()[KEYS])
        self.assertNotEqual(self.state()[KEYS]["default"], b64(bytes([1]) * 32))
        result = self.run_cli("set", "key", data=b"dummy-value")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_runs_value("key", b"dummy-value")

    def test_init_is_idempotent(self):
        before = self.state()
        result = self.run_cli("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"already initialized", result.stderr)
        self.assertEqual(self.state(), before)
        self.assertNotIn(b"TEST key-created", result.stderr)

    def test_existing_key_survives_failed_verification(self):
        before = self.state()
        result = self.run_cli("init", extra={"TEST_DENY": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state(), before)
        self.assertNotIn(b"TEST key-created", result.stderr)

    def test_init_failures_do_not_persist_key(self):
        for extra in ({"TEST_DENY": "1"}, {"TEST_UNAVAILABLE": "1"}, {"TEST_FAIL_RESTORE": "1"},
                      {"TEST_FAIL_ADD": "1"}, {"TEST_FAIL_READ": "1"}):
            with self.subTest(extra=extra):
                self.save({})
                result = self.run_cli("init", extra=extra)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.state(), {})

    def test_init_never_replaces_corrupt_or_lost_key(self):
        for state in ({KEYS: {"default": b64(b"broken")}}, {SECRETS: {"key": b64(b"orphaned")}}):
            with self.subTest(state=state):
                self.save(state)
                result = self.run_cli("init")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.state(), state)
                self.assertNotIn(b"TEST key-created", result.stderr)

    def test_init_concurrent_add_does_not_overwrite_winner(self):
        self.save({})
        result = self.run_cli("init", extra={"TEST_ADD_RACE": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state()[KEYS]["default"], b64(b"concurrent-value"))
        self.assertNotIn(b"TEST updated", result.stderr)

    def test_set_requires_init(self):
        self.save({})
        result = self.run_cli("set", "key", data=b"dummy")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"sec init", result.stderr)
        self.assertEqual(self.state(), {})

    def test_ciphertext_only_is_stored_with_randomized_encryption(self):
        value = b"unique-dummy-secret-123456"
        first = self.run_cli("set", "key", data=value)
        self.assertEqual(first.returncode, 0, first.stderr)
        ciphertext = self.state()[SECRETS]["key"]
        self.assertNotIn(value, base64.b64decode(ciphertext))
        self.assertNotIn(b64(value).encode(), base64.b64decode(ciphertext))
        self.assertNotIn(value, first.stdout + first.stderr)
        self.assertIn(b"TEST authenticated", first.stderr)
        second = self.run_cli("set", "key", data=value)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(self.state()[SECRETS]["key"], ciphertext)
        self.assert_runs_value("key", value)

    def test_replacement_updates_without_delete(self):
        result = self.run_cli("set", "key", items={"key": b"old"}, data=b"new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"TEST updated sec.encrypted.v1/key", result.stderr)
        self.assertNotIn(b"TEST deleted", result.stderr)
        self.assert_runs_value("key", b"new")

    def test_failed_update_preserves_old_value(self):
        result = self.run_cli("set", "key", items={"key": b"old"}, data=b"new", extra={"TEST_FAIL_UPDATE": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST deleted", result.stderr)
        self.assertNotIn(b"TEST added", result.stderr)
        self.assert_runs_value("key", b"old")

    def test_failed_authentication_during_set_preserves_old_value(self):
        result = self.run_cli("set", "key", items={"key": b"old"}, data=b"new", extra={"TEST_DENY": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST updated", result.stderr)
        self.assertNotIn(b"TEST deleted", result.stderr)
        self.assert_runs_value("key", b"old")

    def test_failed_add_reports_error(self):
        result = self.run_cli("set", "key", data=b"new", extra={"TEST_FAIL_ADD": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"stored 'key'", result.stderr)
        self.assertNotIn(SECRETS, self.state())

    def test_concurrent_add_is_updated(self):
        result = self.run_cli("set", "key", data=b"new", extra={"TEST_ADD_RACE": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"TEST deleted", result.stderr)
        self.assert_runs_value("key", b"new")

    def test_invalid_values_are_rejected_before_storage(self):
        for value in (b"", b"\r\n", b"\xff", b"first\0second", b"\0first", b"first\0"):
            with self.subTest(value=value):
                result = self.run_cli("set", "key", data=value)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(b"TEST ", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_invalid_decrypted_values_do_not_run_command(self):
        for value in (b"\xff", b"first\0second", b"\0first", b"first\0"):
            with self.subTest(value=value):
                result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed", items={"key": value})
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")

    def test_unicode_and_multiline_values_are_preserved(self):
        value = "caf\u00e9\nsecond line".encode()
        stored = self.run_cli("set", "key", data=value + b"\r\n")
        self.assertEqual(stored.returncode, 0, stored.stderr)
        self.assert_runs_value("key", value)

    def test_denied_authentication_cannot_be_bypassed(self):
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed",
                              items={"key": b"dummy"}, extra={"TEST_DENY": "1", "SEC_SKIP_BIOMETRY": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"Touch ID denied", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_unavailable_hardware_does_not_launch_command(self):
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed",
                              items={"key": b"dummy"}, extra={"TEST_UNAVAILABLE": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")

    def test_different_valid_private_key_cannot_open_secret(self):
        self.run_cli("set", "key", data=b"dummy-secret")
        state = self.state()
        state[KEYS]["default"] = b64(bytes([2]) * 32)
        self.save(state)
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"different encryption key", result.stderr)
        self.assertNotIn(b"TEST authenticated", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_tampering_wrong_name_version_and_key_fail_closed(self):
        self.run_cli("set", "key", data=b"dummy-secret")
        original = self.state()
        sealed = json.loads(base64.b64decode(original[SECRETS]["key"]))
        variants = []
        for field in ("ciphertext", "encapsulatedKey", "keyID"):
            changed = dict(sealed)
            raw = bytearray(base64.b64decode(changed[field]))
            raw[-1] ^= 1
            changed[field] = b64(raw)
            variants.append(changed)
        variants.extend([{**sealed, "version": 99}, {**sealed, "ciphertext": "not-base64"}])
        for changed in variants:
            with self.subTest(changed=changed):
                self.save({**original, SECRETS: {"key": b64(json.dumps(changed).encode())}})
                result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
        self.save({**original, SECRETS: {"other": original[SECRETS]["key"]}})
        result = self.run_cli("run", "other", "--", "/usr/bin/printf", "executed")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")

    def test_plaintext_in_new_store_is_not_accepted(self):
        state = self.state()
        state[SECRETS] = {"key": b64(b"not-encrypted")}
        self.save(state)
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST authenticated", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_invalid_mappings_fail_before_authentication(self):
        for spec in ("", "=key", "TOKEN=", "BAD-NAME=key", "1key", "caf\u00e9", "TOKEN\n=key"):
            with self.subTest(spec=spec):
                result = self.run_cli("run", spec, "--", "/usr/bin/printf", "executed")
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(b"TEST ", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_duplicate_variables_fail_before_authentication(self):
        for specs in (("api-key", "api_key"), ("TOKEN=first", "TOKEN=second"), ("key", "KEY=key")):
            with self.subTest(specs=specs):
                result = self.run_cli("run", *specs, "--", "/usr/bin/printf", "executed")
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"duplicate environment variable", result.stderr)
                self.assertNotIn(b"TEST ", result.stderr)

    def test_explicit_aliases_support_arbitrary_nonempty_names(self):
        result = self.run_cli("run", "FIRST=1key", "_second2=caf\u00e9", "THIRD==key", "--", "/bin/sh", "-c",
                              'printf "%s:%s:%s" "$FIRST" "$_second2" "$THIRD"',
                              items={"1key": b"one", "caf\u00e9": b"two", "=key": b"three"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"one:two:three")

    def test_empty_secret_name_is_not_stored(self):
        result = self.run_cli("set", "", data=b"value")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST ", result.stderr)

    def test_failed_environment_update_does_not_run_command(self):
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed", items={"key": b"value"},
                              extra={"TEST_FAIL_SETENV": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"could not set environment variable 'KEY'", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_missing_second_secret_fails_before_authentication(self):
        result = self.run_cli("run", "key", "missing", "--", "/usr/bin/printf", "executed", items={"key": b"value"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST authenticated", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_list_marks_names_that_need_an_alias(self):
        result = self.run_cli("list", items={"1key": b"one", "key": b"two"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"1key\t(use VAR=name)\nkey\t$KEY\n")
        self.assertNotIn(b"TEST read", result.stderr)

    def legacy_fixture(self, value=b"old-secret"):
        state = self.state()
        state["sec"] = {"key": b64(value)}
        self.save(state)

    def test_legacy_is_visible_but_never_run_directly(self):
        self.legacy_fixture()
        listed = self.run_cli("list")
        self.assertIn(b"key\t$KEY\tlegacy: migration required", listed.stdout)
        result = self.run_cli("run", "key", "--", "/usr/bin/printf", "executed")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"sec migrate", result.stderr)
        self.assertNotIn(b"TEST read sec/key", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_migration_verifies_persisted_value_and_preserves_legacy(self):
        self.legacy_fixture()
        for _ in range(2):
            result = self.run_cli("migrate", "key")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"migrated and verified", result.stderr)
            self.assertIn(b"legacy copies are still unprotected", result.stderr)
            self.assertEqual(self.state()["sec"]["key"], b64(b"old-secret"))
            self.assert_runs_value("key", b"old-secret")
        self.assertIn(b"legacy copy remains", self.run_cli("list").stdout)

    def test_migration_denial_does_not_read_legacy(self):
        self.legacy_fixture()
        before = self.state()
        result = self.run_cli("migrate", "key", extra={"TEST_DENY": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"TEST read sec/key", result.stderr)
        self.assertEqual(self.state(), before)

    def test_migration_conflict_preserves_both_values(self):
        self.legacy_fixture()
        self.run_cli("set", "key", data=b"new-secret")
        before = self.state()
        result = self.run_cli("migrate", "key")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"neither was changed", result.stderr)
        self.assertEqual(self.state(), before)

    def test_migration_failed_insert_or_race_never_deletes_legacy(self):
        for extra in ({"TEST_FAIL_ADD": "1"}, {"TEST_ADD_RACE": "1"}):
            with self.subTest(extra=extra):
                self.setUp()
                self.legacy_fixture()
                result = self.run_cli("migrate", "key", extra=extra)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.state()["sec"]["key"], b64(b"old-secret"))
                self.assertNotIn(b"TEST deleted", result.stderr)
                self.assertNotIn(b"TEST updated", result.stderr)

    def test_migration_of_invalid_value_preserves_legacy(self):
        self.legacy_fixture(b"bad\0value")
        before = self.state()
        result = self.run_cli("migrate", "key")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state(), before)

    def test_exec_failure_returns_error_without_printing_value(self):
        result = self.run_cli("run", "key", "--", "/nonexistent-sec-test-command", items={"key": b"dummy-secret"})
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"could not exec", result.stderr)
        self.assertNotIn(b"dummy-secret", result.stderr + result.stdout)

    def test_usage_errors_do_not_access_storage(self):
        for args in (("init", "extra"), ("list", "extra"), ("migrate",), ("migrate", ""),
                     ("rm",), ("run", "key"), ("run", "key", "--"), ("run", "key", "--", "")):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(b"TEST ", result.stderr)

    def test_remove_deletes_only_selected_ciphertext(self):
        self.legacy_fixture()
        self.run_cli("set", "key", data=b"dummy")
        key = self.state()[KEYS]
        result = self.run_cli("rm", "key")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("key", self.state()[SECRETS])
        self.assertEqual(self.state()[KEYS], key)
        self.assertIn("key", self.state()["sec"])
        self.assertIn(b"legacy copy remains", result.stderr)

    def test_documented_curl_examples_keep_token_out_of_arguments(self):
        curl = Path(self.directory.name) / "curl"
        curl.write_text(
            '#!/bin/sh\n'
            'for argument do\n'
            '  case "$argument" in *"$API_TOKEN"*) exit 91;; esac\n'
            'done\n'
            '[ "$1" = "-sS" ] && [ "$2" = "--header" ] && [ "$3" = "@-" ] || exit 92\n'
            'IFS= read -r header\n'
            '[ "$header" = "Authorization: Bearer $API_TOKEN" ] || exit 93\n'
            'printf "header received without token in argv"\n'
        )
        curl.chmod(0o755)
        help_text = self.run_cli("--help").stdout.decode()
        for text in ((ROOT / "README.md").read_text(), help_text):
            command = re.search(r"sh -c '([^']+)'", text).group(1)
            result = self.run_cli("run", "api-token", "--", "/bin/sh", "-c", command,
                                  items={"api-token": b"dummy-token"},
                                  extra={"PATH": self.directory.name + os.pathsep + os.environ["PATH"]})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"header received without token in argv")


if __name__ == "__main__":
    unittest.main()
