import unittest
import os
import re
import subprocess
import sys
import tempfile

import gtirb
import gtirb_test_helpers as gth
import dummyso
import hello_world

from pprinter_helpers import pprinter_binary, temp_directory


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

    def test_dummyso_tls(self):
        ir = dummyso.build_tls_gtirb()

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

            # Ensure the TLS symbol is linked
            readelf_output = subprocess.check_output(
                ["readelf", "--dyn-syms", exe_path]
            ).decode(sys.stdout.encoding)
            self.assertRegex(
                readelf_output,
                r"([0-9a-f]+)\s+0\s+TLS\s+GLOBAL\s+DEFAULT\s+UND\s__lib_value",
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

    def test_object(self):
        ir = hello_world.build_gtirb()
        with temp_directory() as test_dir:
            gtirb_path = os.path.join(test_dir, "hello_world.gtirb")
            ir.save_protobuf(gtirb_path)
            object_path = os.path.join(test_dir, "hello_world_rw.o")

            subprocess.check_call(
                [
                    pprinter_binary(),
                    "--ir",
                    gtirb_path,
                    "--binary",
                    object_path,
                    "--object",
                    "--policy",
                    "complete",
                ]
            )
            self.assertTrue(os.path.exists(object_path))

            output = subprocess.check_output(["file", object_path])
            self.assertTrue(b"relocatable" in output)

    def subtest_dynamic_entries(self, sym_init: str, sym_fini: str):
        """
        Test that DT_INIT and DT_FINI entries are recreated
        """
        # Build a GTIRB module with DT_INIT/DT_FINI entries.
        (ir, module) = gth.create_test_module(
            gtirb.Module.FileFormat.ELF,
            gtirb.Module.ISA.X64,
        )

        # Build code blocks
        section_flags = {
            gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Executable,
            gtirb.Section.Flag.Loaded,
            gtirb.Section.Flag.Initialized,
        }

        #    48 31 ff                xor    %rdi,%rdi
        #    0f 05                   syscall
        code_bytes = b"\x48\x31\xff\x0f\x05"
        code_blocks = {}
        addr = 0x10000
        for section_name in (".text", ".init", ".fini"):
            (section, section_bi) = gth.add_section(
                module, section_name, address=addr, flags=section_flags
            )
            code_blocks[section_name] = gth.add_code_block(
                section_bi, code_bytes, {}
            )

            addr += 0x10

        # Build symbols
        symbol_start = gth.add_symbol(module, "_start", code_blocks[".text"])
        module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )

        for section_name, sym_name in (
            (".init", sym_init),
            (".fini", sym_fini),
        ):
            symbol = gth.add_symbol(
                module, sym_name, code_blocks[section_name]
            )
            module.aux_data["elfSymbolInfo"].data[symbol.uuid] = (
                0,
                "FUNC",
                "LOCAL",
                "DEFAULT",
                0,
            )

        # Add DT_INIT and DT_FINI entries
        module.aux_data["dynamicEntries"].data.update(
            {
                ("INIT", code_blocks[".init"].address),
                ("FINI", code_blocks[".fini"].address),
            }
        )

        # Build binary
        with tempfile.TemporaryDirectory() as testdir:
            gtirb_path = os.path.join(testdir, "test.gtirb")
            ir.save_protobuf(gtirb_path)

            exe_path = os.path.join(testdir, "test")
            subprocess.run(
                [
                    pprinter_binary(),
                    "--ir",
                    str(gtirb_path),
                    "--binary",
                    str(exe_path),
                    "--policy",
                    "complete",
                ],
                check=True,
            )

            readelf_output = subprocess.check_output(
                ["readelf", "--syms", "--dynamic", exe_path]
            ).decode(sys.stdout.encoding)

        # Verify readelf output
        for (sym, tag) in ((sym_init, "INIT"), (sym_fini, "FINI")):
            # Find the tag
            pattern = r"0x[0-9a-f]+\s+\(" + tag + r"\)\s+(0x[0-9a-f]+)"
            self.assertRegex(readelf_output, pattern)
            dt_match = re.search(pattern, readelf_output)

            # Find the symbol
            pattern = r"([0-9a-f]+)\s+0\s+FUNC\s+LOCAL\s+DEFAULT\s+\d+\s" + sym
            self.assertRegex(readelf_output, pattern)
            sym_match = re.search(pattern, readelf_output)

            # The symbol and the DT entry should have the same address
            self.assertEqual(
                int(sym_match.group(1), 16), int(dt_match.group(1), 16)
            )

    def test_dynamic_entries(self):
        """
        Set up subtests for DT_INIT and DT_FINI entries
        """
        subtests = (
            # Default names, which don't require -Wl,-init= arguments to the
            # linker
            ("_init", "_fini"),
            # Non-default names
            ("_my_init", "_my_fini"),
        )

        for subtest in subtests:
            with self.subTest(subtest=subtest):
                self.subtest_dynamic_entries(*subtest)
