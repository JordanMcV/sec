import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BuildTests(unittest.TestCase):
    def test_install_from_checkout_named_sec(self):
        with tempfile.TemporaryDirectory(prefix="sec-build-tests-") as directory:
            checkout = Path(directory) / "sec"
            checkout.mkdir()
            shutil.copytree(ROOT / "Sources", checkout / "Sources")
            for name in ("Makefile", "Info.plist"):
                shutil.copy2(ROOT / name, checkout / name)
            prefix = Path(directory) / "install with spaces"
            cache = os.environ.get("SWIFT_MODULE_CACHE_PATH", str(Path(directory) / "cache"))
            subprocess.run([
                "make", "install", f"PREFIX={prefix}",
                f"SWIFTFLAGS=-O -module-cache-path {cache}",
            ], cwd=checkout, check=True, capture_output=True)
            binary = prefix / "bin/sec"
            subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True)
            signature = subprocess.run(["codesign", "-dv", str(binary)],
                                       check=True, capture_output=True, text=True)
            self.assertIn("Sealed Resources=none", signature.stderr)
            self.assertIn("Identifier=dev.jordanmcv.sec", signature.stderr)
            subprocess.run([str(binary), "--help"], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
