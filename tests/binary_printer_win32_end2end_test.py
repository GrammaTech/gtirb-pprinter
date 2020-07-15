import unittest
from pathlib import Path
import os
import subprocess
import sys
import tempfile

hello_world_win32_gtirb = Path("tests", "hello_world_win32.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    def test_generate_binary(self):
        if os.name != "nt":
            return

        base_path = tempfile.mkdtemp()
        out_path = os.path.join(base_path, "hello_world.exe")
        in_path = os.path.abspath(str(hello_world_win32_gtirb))
        subprocess.check_output(
            ["gtirb-pprinter", "--ir", in_path, "--binary", out_path],
            cwd=base_path,
        ).decode(sys.stdout.encoding)
        output_bin = subprocess.check_output(out_path).decode(
            sys.stdout.encoding
        )
        self.assertTrue("hello world" in output_bin)
