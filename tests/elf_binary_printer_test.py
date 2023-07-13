import contextlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import typing
import unittest

import gtirb
import gtirb_test_helpers as gth
import dummyso
import hello_world

from pprinter_helpers import pprinter_binary


@unittest.skipUnless(os.name == "posix", "only runs on Linux")
class ElfBinaryPrinterTests(unittest.TestCase):
    @contextlib.contextmanager
    def binary_print(self, ir: gtirb.IR, *extra_args) -> Path:
        """
        Run binary printer and provide a path to the compiled binary
        """
        with tempfile.TemporaryDirectory() as testdir:
            testdir = Path(testdir)
            gtirb_path = testdir / "test.gtirb"
            exe_path = testdir / "test_rewritten"
            ir.save_protobuf(str(gtirb_path))

            args = [
                pprinter_binary(),
                "--ir",
                gtirb_path,
                "--binary",
                exe_path,
                "--policy",
                "complete",
                *extra_args,
            ]

            subprocess.run(args, check=True)
            self.assertTrue(exe_path.exists())
            yield exe_path

    def find_syms(
        self,
        exe_path: Path,
        syms: typing.List[typing.Tuple[str, str, str, str]],
    ) -> typing.List[typing.Optional[int]]:
        """
        Find symbols in the ELF file at `exe_path` having the provided
        properties: (Type, Binding, Visibility, Name)

        Returns addresses corresponding to each symbol, or None for each
        symbol not found.
        """
        readelf = subprocess.run(
            ["readelf", "--dyn-syms", exe_path],
            check=True,
            capture_output=True,
            text=True,
        )

        addrs = []
        template = r"([0-9a-f]+)\s+\d+\s+{}\s+{}\s+{}\s+(UND|\d+)\s+{}"
        for sym_type, binding, vis, name in syms:
            match = re.search(
                template.format(sym_type, binding, vis, name), readelf.stdout
            )

            addrs.append(match.group(1) if match else None)

        return addrs

    def assert_libs_in_ldd(self, exe_path: Path, libs: typing.List[str]):
        """
        Asserts each lib in `libs` is linked by the ELF at `exe_path`
        """
        ldd = subprocess.run(
            ["ldd", exe_path], check=True, capture_output=True, text=True
        )
        for lib in libs:
            self.assertIn(lib, ldd.stdout)

    def test_dummyso(self):
        """
        Test printing a simple GTIRB with --dummy-so.
        """
        ir = dummyso.build_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as exe_path:
            # Make sure the .so libs have been built
            libdir = Path(__file__).parent / "dummyso_libs"
            self.assertTrue(libdir.exists())
            subprocess.run("make", cwd=libdir, check=True)
            self.assertTrue((libdir / "libmya.so").exists())
            self.assertTrue((libdir / "libmyb.so").exists())

            # Run the resulting binary with the directory containing the actual
            # .so libs in LD_LIBRARY_PATH, so the loader can find them.
            exec_proc = subprocess.run(
                str(exe_path),
                env={"LD_LIBRARY_PATH": libdir},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue("a() invoked!" in exec_proc.stdout)
            self.assertTrue("b() invoked!" in exec_proc.stdout)

    def test_dummyso_plt_sec(self):
        """
        Test printing a GTIRB where a symbol is attached to a PLT entry in
        .plt.sec.

        Verify that the symbol is generated in dummyso.
        """
        ir = dummyso.build_plt_sec_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as exe_path:
            # Make sure the .so libs have been built
            libdir = Path(__file__).parent / "dummyso_libs"
            self.assertTrue(libdir.exists())
            subprocess.run("make", cwd=libdir, check=True)
            self.assertTrue((libdir / "libmya.so").exists())

            # Run the resulting binary with the directory containing the actual
            # .so libs in LD_LIBRARY_PATH, so the loader can find them.
            exec_proc = subprocess.run(
                str(exe_path),
                env={"LD_LIBRARY_PATH": libdir},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue("a() invoked!" in exec_proc.stdout)

    def test_dummyso_copy_relocated(self):
        """
        Test printing a GTIRB with --dummy-so where its only external symbols
        are members of a single COPY-relocated group.

        Verify that the final binary's symbols are generated correctly.
        """
        ir = dummyso.build_copy_relocated_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as exe_path:
            self.assert_libs_in_ldd(exe_path, "libvalue.so")

            # Ensure the GLOBAL and WEAK versions of the COPY-relocated symbol
            # refer to the same address; this verifies that they were grouped
            # together for printing.
            sym_addr, sym_addr_weak = self.find_syms(
                exe_path,
                [
                    ("OBJECT", "GLOBAL", "DEFAULT", "__lib_value"),
                    ("OBJECT", "WEAK", "DEFAULT", "__lib_value_weak"),
                ],
            )

            self.assertIsNotNone(sym_addr)
            self.assertIsNotNone(sym_addr_weak)

            # Both symbols should be at the same address.
            self.assertEqual(sym_addr, sym_addr_weak)

    def test_dummyso_tls(self):
        """
        Test printing a GTIRB that links a TLS symbol with --dummy-so
        """
        ir = dummyso.build_tls_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as exe_path:
            self.assert_libs_in_ldd(exe_path, "libvalue.so")

            # Ensure the TLS symbol is linked
            addr = self.find_syms(
                exe_path, [("TLS", "GLOBAL", "DEFAULT", "__lib_value")]
            )[0]
            self.assertIsNotNone(addr)

    def test_dummyso_versioned_syms(self):
        """
        Test printing a GTIRB with --dummy-so where there are multiple external
        versioned symbols of the same name
        """
        ir = dummyso.build_versioned_syms_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as exe_path:
            self.assert_libs_in_ldd(exe_path, "libmya.so")

            # Ensure the symbols are present
            addrs = self.find_syms(
                exe_path,
                [
                    ("FUNC", "GLOBAL", "DEFAULT", "a@LIBA_1.0"),
                    ("FUNC", "GLOBAL", "DEFAULT", "a@LIBA_2.0"),
                ],
            )
            for addr in addrs:
                self.assertIsNotNone(addr)

    def test_use_gcc(self):
        """
        Test --use-gcc, both with a gcc in PATH and with a full path to gcc
        """
        ir = hello_world.build_gtirb()

        which = subprocess.run(
            ["which", "gcc"],
            check=True,
            capture_output=True,
            text=True,
        )
        gcc_full_path = which.stdout.strip()

        gccs = ("gcc", gcc_full_path)

        for gcc in gccs:
            with self.subTest(gcc=gcc):
                with self.binary_print(ir, "--use-gcc", gcc):
                    # Just verify binary_print succeeded.
                    pass

    def test_object(self):
        """
        Test the --object argument
        """
        ir = hello_world.build_gtirb()
        with self.binary_print(ir, "--object") as object_path:
            output = subprocess.run(
                ["file", object_path],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue("relocatable" in output.stdout)

    def subtest_dyn_option(
        self, mode: str, shared_option: str, pie: bool, shared: bool
    ):
        """
        Test that shared/pie options are automatically set up right.
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
        section_name = ".text"
        (section, section_bi) = gth.add_section(
            module, section_name, address=addr, flags=section_flags
        )
        code_blocks[section_name] = gth.add_code_block(
            section_bi, code_bytes, {}
        )

        if mode == "EXEC":
            module.aux_data["binaryType"].data.append("EXEC")
        elif mode == "SHARED":
            module.aux_data["binaryType"].data.append("DYN")
            module.aux_data["binaryType"].data.append("SHARED")
        elif mode == "PIE":
            module.aux_data["binaryType"].data.append("DYN")
            module.aux_data["binaryType"].data.append("PIE")

        # Build symbols
        symbol_main = gth.add_symbol(module, "foo", code_blocks[".text"])
        module.aux_data["elfSymbolInfo"].data[symbol_main.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )

        # Build binary
        with tempfile.TemporaryDirectory() as testdir:
            gtirb_path = os.path.join(testdir, "test.gtirb")
            ir.save_protobuf(gtirb_path)

            output_path = os.path.join(testdir, "test")
            pprinter_cmd = [
                pprinter_binary(),
                "--ir",
                str(gtirb_path),
                "--binary",
                str(output_path),
                "--policy",
                "complete",
                "--shared",
            ]
            if shared_option:
                pprinter_cmd += [shared_option]
            output = subprocess.check_output(pprinter_cmd).decode(
                sys.stdout.encoding
            )

            if pie:
                self.assertIn(" -pie", output)
            else:
                self.assertNotIn(" -pie", output)

            if shared:
                self.assertIn("-shared", output)
            else:
                self.assertNotIn("-shared", output)

            self.assertTrue(os.path.exists(output_path))

    def test_dyn_option(self):
        """
        Set up subtests for shared/pie option
        """
        subtests = (
            ("EXEC", "yes", False, True),
            ("EXEC", "no", False, False),
            ("EXEC", "auto", False, False),
            ("SHARED", "yes", False, True),
            ("SHARED", "no", True, False),
            ("SHARED", "auto", False, True),
            ("SHARED", "", False, True),
            ("PIE", "yes", False, True),
            ("PIE", "no", True, False),
            ("PIE", "auto", True, False),
        )

        for subtest in subtests:
            with self.subTest(subtest=subtest):
                self.subtest_dyn_option(*subtest)
