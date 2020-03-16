import unittest
from pathlib import Path
import subprocess
import sys

two_modules_gtirb = Path("tests", "two_modules.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    def test_generate_binary(self):
        output = subprocess.check_output(
            [
                "gtirb-binary-printer",
                "--ir",
                str(two_modules_gtirb),
                "-b",
                "/tmp/two_modules",
                "--compiler-args",
                "-no-pie",
            ]
        ).decode(sys.stdout.encoding)
        self.assertTrue("Calling compiler" in output)
        output_bin = subprocess.check_output("/tmp/two_modules").decode(
            sys.stdout.encoding
        )
        self.assertTrue("!!!Hello World!!!" in output_bin)
