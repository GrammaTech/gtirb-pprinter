import unittest
from pathlib import Path
import os
import subprocess
import sys
import tempfile

two_modules_gtirb = Path("tests", "two_modules.gtirb")


class TestPrintToStdout(unittest.TestCase):
    def test_print_module0(self):
        output = subprocess.check_output(
            ["gtirb-pprinter", "--ir", str(two_modules_gtirb), "-m", "0"]
        ).decode(sys.stdout.encoding)
        self.assertTrue(".globl main" in output)
        self.assertFalse(".globl fun" in output)

    def test_print_module1(self):
        output = subprocess.check_output(
            ["gtirb-pprinter", "--ir", str(two_modules_gtirb), "-m", "1"]
        ).decode(sys.stdout.encoding)
        self.assertTrue(".globl fun" in output)
        self.assertFalse(".globl main" in output)


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
