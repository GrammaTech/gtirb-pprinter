import unittest
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

two_modules_gtirb = Path("tests", "two_modules.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    def test_binaries(self):
        if os.name == "nt":
            return

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

    def test_keep_function(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".s")
        try:
            tmp.close()

            output = subprocess.check_output(
                [
                    "gtirb-pprinter",
                    "--ir",
                    str(two_modules_gtirb),
                    "-a",
                    tmp.name,
                    "--keep-function",
                    "_start",
                ]
            ).decode(sys.stdout.encoding)
            self.assertTrue("assembly written to" in output)
            with open(tmp.name) as assembly:
                self.assertTrue("_start:" in assembly.read().splitlines())
        finally:
            tmp = Path(tmp.name)
            if tmp.exists():
                tmp.unlink()
            extra = tmp.parent / (tmp.stem + "1" + tmp.suffix)
            if extra.exists():
                extra.unlink()
