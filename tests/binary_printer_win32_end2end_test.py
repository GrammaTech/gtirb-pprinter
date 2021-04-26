import unittest
from pathlib import Path
import os
import subprocess
import sys
import tempfile

from pprinter_helpers import TESTS_DIR

pe32plus_gtirb = Path(TESTS_DIR, "ConsoleApplication1.exe.gtirb")


class TestBinaryGeneration(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "only runs on Windows")
    def test_generate_binary(self):
        base_path = tempfile.mkdtemp()
        # This is a pe32+ console application that will load a resource test
        # string and display it on the console.
        out_path = os.path.join(base_path, "ConsoleApplication1.exe")
        in_path = os.path.abspath(str(pe32plus_gtirb))
        subprocess.check_output(
            ["gtirb-pprinter", "--ir", in_path, "--binary", out_path],
            cwd=base_path,
        ).decode(sys.stdout.encoding)
        output = subprocess.check_output(out_path).decode(sys.stdout.encoding)
        self.assertTrue("Test resource string" in output)
