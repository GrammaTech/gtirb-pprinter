import unittest
from pathlib import Path
import os
import shutil
import subprocess
import sys

from pprinter_helpers import TESTS_DIR

two_modules_gtirb = Path(TESTS_DIR, "two_modules.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "only runs on Linux")
    def test_binaries(self):
        shutil.rmtree("/tmp/two_mods", ignore_errors=True)
        os.mkdir("/tmp/two_mods")
        try:
            subprocess.check_output(
                [
                    "gtirb-pprinter",
                    "--ir",
                    str(two_modules_gtirb),
                    "--asm",
                    "/tmp/two_mods/foo.s",
                ]
            ).decode(sys.stdout.encoding)

            subprocess.check_output(
                [
                    "gcc",
                    "-no-pie",
                    "-shared",
                    "/tmp/two_mods/foo1.s",
                    "-o",
                    "/tmp/two_mods/fun.so",
                ]
            ).decode(sys.stdout.encoding)

            subprocess.check_output(
                [
                    "gcc",
                    "-no-pie",
                    "/tmp/two_mods/foo.s",
                    "/tmp/two_mods/fun.so",
                    "-Wl,-rpath,/tmp/two_mods",
                    "-o",
                    "/tmp/two_mods/a.out",
                ]
            ).decode(sys.stdout.encoding)

            output_bin = subprocess.check_output("/tmp/two_mods/a.out").decode(
                sys.stdout.encoding
            )
            self.assertTrue("!!!Hello World!!!" in output_bin)
        finally:
            shutil.rmtree("/tmp/two_mods")
