import unittest
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import shutil

two_modules_gtirb = Path("tests", "two_modules.gtirb")


class TestPrintToStdout(unittest.TestCase):
    def test_print_module0(self):
        output = subprocess.check_output(
            ["gtirb-pprinter", "--ir", str(two_modules_gtirb), "-m", "0"]
        ).decode(sys.stdout.encoding)
        self.assertTrue("\nmain:" in output)
        self.assertFalse("\nfun:" in output)

    def test_print_module1(self):
        output = subprocess.check_output(
            ["gtirb-pprinter", "--ir", str(two_modules_gtirb), "-m", "1"]
        ).decode(sys.stdout.encoding)
        self.assertTrue("\nfun:" in output)
        self.assertFalse("\nmain" in output)


class TestPrintToFile(unittest.TestCase):
    def test_print_two_modules(self):
        path = os.path.join(tempfile.mkdtemp(), "two_modules{}.s")
        subprocess.check_output(
            [
                "gtirb-pprinter",
                "--ir",
                str(two_modules_gtirb),
                "--asm",
                path.format(""),
            ]
        ).decode(sys.stdout.encoding)
        with open(path.format(""), "r") as f:
            self.assertTrue(".globl main" in f.read())
        with open(path.format("1"), "r") as f:
            self.assertTrue(".globl fun" in f.read())


class TestPrettyPrinter(unittest.TestCase):
    def test_avx512_att(self):
        # This test ensures that we do not regress on the following issue:
        # git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/330
        temp_dir = tempfile.mkdtemp()
        os.mkdir(temp_dir)

        try:
            # test if AVX512 instructions in assembly
            asm_path = os.path.join(temp_dir, "test_avx512_att.s")
            subprocess.check_output(
                [
                    "gtirb-pprinter",
                    "--ir",
                    "tests/test_avx512_att.gtirb",
                    "--asm",
                    asm_path,
                    "--syntax",
                    "att",
                ]
            ).decode(sys.stdout.encoding)
            with open(asm_path, "r") as f:
                self.assertTrue("vpaddq" in f.read())

            # test if assembly file can be compiled
            bin_path = os.path.join(temp_dir, "test_avx512_att.roundtrip")
            subprocess.check_output(
                [
                    "gtirb-pprinter",
                    "--ir",
                    "tests/test_avx512_att.gtirb",
                    "--binary",
                    bin_path,
                    "--syntax",
                    "att",
                ]
            ).decode(sys.stdout.encoding)
        finally:
            # clean up
            shutil.rmtree(temp_dir, ignore_errors=True)
