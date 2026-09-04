import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BuildTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="sec-build-tests-")
        self.addCleanup(directory.cleanup)
        self.checkout = Path(directory.name) / "sec"
        self.checkout.mkdir()
        shutil.copytree(ROOT / "Sources", self.checkout / "Sources")
        for name in ("Makefile", "Info.plist"):
            shutil.copy2(ROOT / name, self.checkout / name)
        self.prefix = Path(directory.name) / "install with spaces"
        cache = os.environ.get("SWIFT_MODULE_CACHE_PATH", str(Path(directory.name) / "cache"))
        self.make_args = ["make", f"PREFIX={self.prefix}", f"SWIFTFLAGS=-O -module-cache-path {cache}"]

    def make(self, *args, check=True):
        return subprocess.run([*self.make_args, *args], cwd=self.checkout,
                              check=check, capture_output=True, text=True)

    def test_install_from_checkout_named_sec(self):
        self.make("install")
        binary = self.prefix / "bin/sec"
        subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True)
        signature = subprocess.run(["codesign", "-dv", str(binary)],
                                   check=True, capture_output=True, text=True)
        self.assertIn("Sealed Resources=none", signature.stderr)
        self.assertIn("Identifier=dev.jordanmcv.sec", signature.stderr)
        subprocess.run([str(binary), "--help"], check=True, capture_output=True)

    def test_changed_identity_is_honored_and_failure_blocks_install(self):
        self.make("build")
        missing_identity = f"sec-test-missing-{self.checkout.parent.name}"
        result = self.make("install", f"SIGN_IDENTITY={missing_identity}", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(missing_identity, result.stdout)
        self.assertNotIn("swiftc", result.stdout)
        self.assertFalse((self.prefix / "bin/sec").exists())
        recovered = self.make("sign")
        self.assertIn("codesign", recovered.stdout)
        self.assertNotIn("swiftc", recovered.stdout)


if __name__ == "__main__":
    unittest.main()
