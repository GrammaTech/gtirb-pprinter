import unittest
import os
import re
import subprocess
import sys
import tempfile

import dummyso
import hello_world

from pprinter_helpers import pprinter_binary


@unittest.skipUnless(os.name == "posix", "only runs on Linux")
class ElfBinaryPrinterTests(unittest.TestCase):
    def test_dummyso(self):
        ir = dummyso.build_gtirb()

        with tempfile.TemporaryDirectory() as testdir:
            gtirb_path = os.path.join(testdir, "dummyso.gtirb")
            ir.save_protobuf(gtirb_path)

            exe_path = os.path.join(testdir, "dummyso_rewritten")

            # Check that we can automatically build a binary that has
            # dependences on .so files without having those .so files
            # be present.
            output = subprocess.check_output(
                [
                    pprinter_binary(),
                    "--ir",
                    str(gtirb_path),
                    "--binary",
                    str(exe_path),
                    "--dummy-so",
                    "yes",
                    "--policy",
                    "complete",
                ]
            ).decode(sys.stdout.encoding)
            self.assertIn("Compiler arguments:", output)
            self.assertTrue(os.path.exists(exe_path))

            # Make sure the .so libs have been built
            libdir = os.path.join(os.path.dirname(__file__), "dummyso_libs")
            self.assertTrue(os.path.exists(libdir))
            subprocess.run(
                "make",
                cwd=libdir,
            )
            self.assertTrue(os.path.exists(os.path.join(libdir, "libmya.so")))
            self.assertTrue(os.path.exists(os.path.join(libdir, "libmyb.so")))

            # Run the resulting binary with the directory containing the actual
            # .so libs in LD_LIBRARY_PATH, so the loader can find them.
            output_bin = subprocess.check_output(
                exe_path, env={"LD_LIBRARY_PATH": libdir}
            ).decode(sys.stdout.encoding)
            self.assertTrue("a() invoked!" in output_bin)
            self.assertTrue("b() invoked!" in output_bin)

    def test_dummyso_copy_relocated(self):
        """
        Build a GTIRB where its only external symbols are members of a single
        COPY-relocated group. Verify that the final binary's symbols are
        generated correctly.
        """
        ir = dummyso.build_copy_relocated_gtirb()

        with tempfile.TemporaryDirectory() as testdir:
            gtirb_path = os.path.join(testdir, "dummyso.gtirb")
            ir.save_protobuf(gtirb_path)

            exe_path = os.path.join(testdir, "dummyso_rewritten")

            # Check that we can automatically build a binary that has
            # dependences on .so files without having those .so files
            # be present.
            output = subprocess.check_output(
                [
                    pprinter_binary(),
                    "--ir",
                    str(gtirb_path),
                    "--binary",
                    str(exe_path),
                    "--dummy-so",
                    "yes",
                    "--policy",
                    "complete",
                ]
            ).decode(sys.stdout.encoding)
            self.assertIn("Compiler arguments:", output)
            self.assertTrue(os.path.exists(exe_path))

            # Ensure the library is linked
            ldd_output = subprocess.check_output(["ldd", exe_path]).decode(
                sys.stdout.encoding
            )
            self.assertIn("libvalue.so", ldd_output)

            # Ensure the GLOBAL and WEAK versions of the COPY-relocated symbol
            # refer to the same address; this verifies that they were grouped
            # together for printing.
            readelf_output = subprocess.check_output(
                ["readelf", "--dyn-syms", exe_path]
            ).decode(sys.stdout.encoding)

            # The WEAK and GLOBAL symbols should both be present
            sym_match = re.search(
                r"([0-9a-f]+)\s+4\s+OBJECT\s+GLOBAL.+__lib_value",
                readelf_output,
            )
            sym_match_weak = re.search(
                r"([0-9a-f]+)\s+4\s+OBJECT\s+WEAK.+__lib_value_weak",
                readelf_output,
            )
            self.assertIsNotNone(sym_match)
            self.assertIsNotNone(sym_match_weak)

            # Both symbols should be at the same address.
            self.assertEqual(
                int(sym_match.group(1), 16), int(sym_match_weak.group(1), 16)
            )

    def test_use_gcc(self):
        """
        Test --use-gcc, both with a gcc in PATH and with a full path to gcc
        """
        ir = hello_world.build_gtirb()

        gcc_full_path = (
            subprocess.check_output(["which", "gcc"])
            .decode(sys.stdout.encoding)
            .strip()
        )
        gccs = ("gcc", gcc_full_path)

        for gcc in gccs:
            with self.subTest(gcc=gcc):
                with tempfile.TemporaryDirectory() as testdir:
                    gtirb_path = os.path.join(testdir, "hello_world.gtirb")
                    ir.save_protobuf(gtirb_path)

                    exe_path = os.path.join(testdir, "hello_world_rewritten")
                    subprocess.check_call(
                        [
                            pprinter_binary(),
                            "--ir",
                            gtirb_path,
                            "--binary",
                            exe_path,
                            "--policy",
                            "complete",
                            "--use-gcc",
                            gcc,
                        ]
                    )
                    self.assertTrue(os.path.exists(exe_path))
