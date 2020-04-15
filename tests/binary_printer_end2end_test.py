import unittest
from pathlib import Path
import subprocess
import sys

ex1_gtirb = Path("tests", "ex1.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    def test_generate_binary(self):
        output = subprocess.check_output(
            [
                "gtirb-binary-printer",
                "--ir",
                str(ex1_gtirb),
                "--binary",
                "/tmp/ex1",
                "--compiler-args",
                "-no-pie",
            ]
        ).decode(sys.stdout.encoding)
        self.assertTrue("Calling compiler" in output)
        output_bin = subprocess.check_output("/tmp/ex1").decode(
            sys.stdout.encoding
        )
        self.assertTrue("!!!Hello World!!!" in output_bin)
