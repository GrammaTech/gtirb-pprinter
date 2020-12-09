import unittest
from pathlib import Path
import os
import subprocess
import sys
import tempfile

pe32plus_gtirb = Path("tests", "project1.exe.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    def test_generate_binary(self):
        if os.name != "nt":
            return

        base_path = tempfile.mkdtemp()
        # This is a pe32+ gui application that will bring up a gui, delay 1s
        # and then exit with exit code 100.
        out_path = os.path.join(base_path, "project1.exe")
        in_path = os.path.abspath(str(pe32plus_gtirb))
        subprocess.check_output(
            ["gtirb-pprinter", "--ir", in_path, "--binary", out_path],
            cwd=base_path,
        ).decode(sys.stdout.encoding)
        ec = subprocess.call(out_path).decode(sys.stdout.encoding)
        self.assertTrue(ec == 1)
