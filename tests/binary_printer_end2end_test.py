from typing import Iterable, Union, Tuple
import unittest
from pathlib import Path
import os
import shutil
import subprocess
import sys
import dummyso
import tempfile
import gtirb

from pprinter_helpers import TESTS_DIR, pprinter_binary, run_binary_pprinter_mock
import gtirb_helpers as helpers

two_modules_gtirb = Path(TESTS_DIR, "two_modules.gtirb")
use_ldlinux_gtirb = Path(TESTS_DIR, "ipcmk.gtirb")


def get_test_ir(binary_type: Union[Iterable[str], None]=None
    )-> Tuple[gtirb.IR, gtirb.Module]:
    ir, m = helpers.create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type
    )
    helpers.add_section(m, ".dynamic")
    _, bi = helpers.add_text_section(m)
    main = helpers.add_code_block(bi, b"\xC3")
    helpers.add_function(m, "main", main)

    return ir, m

class TestBinaryGeneration(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "only runs on Linux")
    def test_two_modules(self):
        shutil.rmtree("/tmp/two_mods", ignore_errors=True)
        os.mkdir("/tmp/two_mods")
        try:
            subprocess.check_output(
                [
                    pprinter_binary(),
                    "--ir",
                    str(two_modules_gtirb),
                    "--asm",
                    "/tmp/two_mods/foo.", 
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

    @unittest.skipUnless(os.name == "posix", "only runs on Linux")
    def test_ldlinux_dep(self):
        # Check that a binary with a known dependence on ld-linux.so does
        # not try to explicity link with it, as the link should be implicit.
        # Just check that the binary causes no compiler errors; this binary
        # was made on CentOS and thus may not run on all systems.

        # Create a dynamic ELF binary with a trivial main() that just returns
        ir, m = get_test_ir(["DYN"])

        m.aux_data["libraries"].data.append("ld-linux-x86-64.so.2")
        output = run_binary_pprinter_mock(ir,[]).stdout.decode(sys.stdout.encoding)

        self.assertIn("Compiler arguments:", output)
        self.assertNotIn("ld-linux", output)

    @unittest.skipUnless(os.name == "posix", "only runs on Linux")
    def test_dummyso(self):
        ir = dummyso.build_gtirb()

        with tempfile.TemporaryDirectory() as testdir:
            testdir = tempfile.mkdtemp()

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
                "make", cwd=libdir,
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

    @unittest.skipUnless(os.name=="posix", "only runs on Linux") # TODO: is this true?
    def test_two_modules_new(self):
        ir, m1 = get_test_ir()
        m2 = gtirb.Module(isa=m1.isa, file_format=m1.file_format, name="test2")
        m2.ir = ir

        helpers.add_standard_aux_data_tables(m2)

        _, bi = helpers.add_text_section(m2)
        instrs = b"" # TODO: FIGURE OUT / GET BYTES TO PUT HERE 
        block = helpers.add_code_block(bi, instrs)
        helpers.add_function(m2, "f1", block)

        
        # TODO: what should we be checking here? 
        output = run_binary_pprinter_mock(ir, []).stdout.decode(sys.stdout.encoding)






