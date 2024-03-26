import os
from pathlib import Path
import subprocess
import typing
import unittest

import gtirb
import gtirb_test_helpers as gth
import dummyso
import hello_world

from pprinter_helpers import (
    BinaryPPrinterTest,
    run_asm_pprinter,
    run_asm_pprinter_with_version_script,
)


@unittest.skipUnless(os.name == "posix", "only runs on Linux")
class ElfBinaryPrinterTests(BinaryPPrinterTest):
    def readelf(self, path: Path, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["readelf", path, *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def assert_readelf_syms(
        self,
        readelf: typing.Union[str, Path],
        *syms: typing.List[typing.Tuple[str, str, str, str]],
    ) -> typing.List[int]:
        """
        Assert that a symbol is present in the given readelf output, and return
        its address

        The first argument can either be a Path (in which readelf --dyn-syms is
        run on it) or an existing readelf output string.
        """
        if isinstance(readelf, Path):
            readelf = self.readelf(readelf, "--dyn-syms").stdout

        pattern = r"([0-9a-f]+)\s+\d+\s+{}\s+{}\s+{}\s+(UND|\d+)\s+{}\s+"
        return [
            self.assertRegexMatch(readelf, pattern.format(*s)).group(1)
            for s in syms
        ]

    def assert_libs_in_ldd(self, exe_path: Path, libs: typing.List[str]):
        """
        Asserts each lib in `libs` is linked by the ELF at `exe_path`
        """
        ldd = subprocess.run(
            ["ldd", exe_path], check=True, capture_output=True, text=True
        )
        for lib in libs:
            self.assertIn(lib, ldd.stdout)

    def build_basic_ir(
        self,
    ) -> typing.Tuple[gtirb.IR, gtirb.Module, gtirb.ByteInterval]:
        """
        Build a generic IR with a _start procedure.

        :returns (ir, module, text-byte-interval)
        """
        ir, module = gth.create_test_module(
            gtirb.Module.FileFormat.ELF,
            gtirb.Module.ISA.X64,
        )
        text_section, text_bi = gth.add_text_section(module)

        # For the following code:
        #    48 31 c0                xor    %rax,%rax
        #    48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
        #    48 31 ff                xor    %rdi,%rdi
        #    0f 05                   syscall
        cb = gth.add_code_block(
            text_bi,
            b"\x48\x31\xc0"
            b"\x48\xc7\xc0\x3c\x00\x00\x00"
            b"\x48\x31\xff"
            b"\x0f\x05",
        )
        symbol_start = gth.add_symbol(module, "_start", cb)
        module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        return ir, module, text_bi

    def test_dummyso(self):
        """
        Test printing a simple GTIRB with --dummy-so.
        """
        ir = dummyso.build_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as result:
            # Make sure the .so libs have been built
            libdir = Path(__file__).parent / "dummyso_libs"
            self.assertTrue(libdir.exists())
            subprocess.run("make", cwd=libdir, check=True)
            self.assertTrue((libdir / "libmya.so").exists())
            self.assertTrue((libdir / "libmyb.so").exists())

            # Run the resulting binary with the directory containing the actual
            # .so libs in LD_LIBRARY_PATH, so the loader can find them.
            exec_proc = subprocess.run(
                str(result.path),
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
        with self.binary_print(ir, "--dummy-so", "yes") as result:
            # Make sure the .so libs have been built
            libdir = Path(__file__).parent / "dummyso_libs"
            self.assertTrue(libdir.exists())
            subprocess.run("make", cwd=libdir, check=True)
            self.assertTrue((libdir / "libmya.so").exists())
            self.assertTrue((libdir / "libmyb.so").exists())

            # Run the resulting binary with the directory containing the actual
            # .so libs in LD_LIBRARY_PATH, so the loader can find them.
            exec_proc = subprocess.run(
                str(result.path),
                env={"LD_LIBRARY_PATH": libdir},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue("a() invoked!" in exec_proc.stdout)
            self.assertTrue("b() invoked!" in exec_proc.stdout)

            # Ensure the bindings of a and b are GLOBAL and WEAK, respectively.
            self.assert_readelf_syms(
                result.path,
                ("FUNC", "GLOBAL", "DEFAULT", "a"),
                ("FUNC", "WEAK", "DEFAULT", "b"),
            )

    def test_dummyso_copy_relocated(self):
        """
        Test printing a GTIRB with --dummy-so where its only external symbols
        are members of a single COPY-relocated group.

        Verify that the final binary's symbols are generated correctly.
        """
        ir = dummyso.build_copy_relocated_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as result:
            self.assert_libs_in_ldd(result.path, "libvalue.so")

            # Ensure the GLOBAL and WEAK versions of the COPY-relocated symbol
            # refer to the same address; this verifies that they were grouped
            # together for printing.
            sym_addr, sym_addr_weak = self.assert_readelf_syms(
                result.path,
                ("OBJECT", "GLOBAL", "DEFAULT", "__lib_value"),
                ("OBJECT", "WEAK", "DEFAULT", "__lib_value_weak"),
            )
            # Both symbols should be at the same address.
            self.assertEqual(sym_addr, sym_addr_weak)

    def test_dummyso_tls(self):
        """
        Test printing a GTIRB that links a TLS symbol with --dummy-so
        """
        ir = dummyso.build_tls_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as result:
            self.assert_libs_in_ldd(result.path, "libvalue.so")

            # Ensure the TLS symbol is linked
            self.assert_readelf_syms(
                result.path,
                ("TLS", "GLOBAL", "DEFAULT", "__lib_value@LIBVALUE_1.0"),
            )

    def test_dummyso_versioned_syms(self):
        """
        Test printing a GTIRB with --dummy-so where there are multiple external
        versioned symbols of the same name
        """
        ir = dummyso.build_versioned_syms_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes") as result:
            self.assert_libs_in_ldd(result.path, "libmya.so")

            # Ensure the symbols are present
            self.assert_readelf_syms(
                result.path,
                ("FUNC", "GLOBAL", "DEFAULT", "a@LIBA_1.0"),
                ("FUNC", "GLOBAL", "DEFAULT", "a@LIBA_2.0"),
            )

    def test_dummyso_weak_versioned_sym_shared(self):
        """
        Test printing a GTIRB with --dummy-so where there are multiple external
        versioned symbols of the same name

        Fails if gtirb-pprinter does not apply --no-as-needed
        """
        ir = dummyso.build_weak_versioned_sym_gtirb()
        with self.binary_print(ir, "--dummy-so", "yes", "--shared") as result:
            self.assert_libs_in_ldd(result.path, "libmya.so")

            # Ensure the symbols are present
            self.assert_readelf_syms(
                result.path,
                ("FUNC", "WEAK", "DEFAULT", "a@LIBA_1.0"),
            )

    def test_dummyso_no_libs(self):
        """
        Test printing a GTIRB that has no libraries with --dummy-so=yes
        """
        ir, _, _ = self.build_basic_ir()

        with self.binary_print(ir, "--dummy-so", "yes"):
            # Just verify binary_print succeeded.
            pass

    def test_dummyso_version_script(self):
        """
        Test printing version script
        """
        ir, module, _ = self.build_basic_ir()

        proxy_foo = gth.add_proxy_block(module)
        symbol_foo = gth.add_symbol(module, "foo", proxy_foo)
        module.aux_data["elfSymbolInfo"].data[symbol_foo.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        proxy_bar = gth.add_proxy_block(module)
        symbol_bar = gth.add_symbol(module, "bar", proxy_bar)
        module.aux_data["elfSymbolInfo"].data[symbol_bar.uuid] = (
            0,
            "FUNC",
            "LOCAL",
            "DEFAULT",
            0,
        )
        module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
            type_name=(
                "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,"
                "mapping<string,mapping<uint16_t,string>>,"
                "mapping<UUID,tuple<uint16_t,bool>>>"
            ),
            data=(
                # ElfSymVerDefs
                {1: (["LIBA_1.0"], 0), 2: (["LIBA_2.0"], 0)},
                # ElfSymVerNeeded
                {"libmya.so": {1: "LIBA_1.0", 2: "LIBA_2.0"}},
                # ElfSymbolVersionsEntries
                {
                    symbol_foo.uuid: (1, False),
                    symbol_bar.uuid: (2, False),
                },
            ),
        )

        vs = run_asm_pprinter_with_version_script(ir)

        pattern1 = r"LIBA_1.0\s+{\s+global:\s+foo;\s+local:\s+\*;\s+};"
        self.assertRegexMatch(vs, pattern1)
        pattern2 = r"LIBA_2.0\s+{\s+local:\s+\*;\s+};"
        self.assertRegexMatch(vs, pattern2)
        self.assertTrue("bar" not in vs)

    def test_base_version(self):
        """
        Make sure that base version is not printed out
        """
        ir, module, bi = self.build_basic_ir()

        foo_block = gth.add_code_block(bi, b"\xC3")
        foo_uuid = gth.add_function(module, "foo", foo_block)

        # Get the foo function symbol
        symbol_foo = module.aux_data["functionNames"].data[foo_uuid]
        module.aux_data["elfSymbolInfo"].data[symbol_foo.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        # Create another symbol pointing to the same block
        symbol_foo2 = gth.add_symbol(module, "foo", foo_block)
        module.aux_data["elfSymbolInfo"].data[symbol_foo2.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
            type_name=(
                "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,"
                "mapping<string,mapping<uint16_t,string>>,"
                "mapping<UUID,tuple<uint16_t,bool>>>"
            ),
            data=(
                # ElfSymVerDefs
                {
                    1: (["LIBA_1.0"], 0),
                    # Flags=1: base version
                    2: (["libmya.so"], 1),
                },
                # ElfSymVerNeeded
                {"libmya.so": {1: "LIBA_1.0"}},
                # ElfSymbolVersionsEntries
                {
                    symbol_foo.uuid: (1, True),
                    # symbol_foo2 gets the base version
                    symbol_foo2.uuid: (2, True),
                },
            ),
        )

        asm = run_asm_pprinter(ir)
        print(asm)

        self.assertRegexMatch(asm, r"foo@LIBA_1.0")
        # The base version should not be printed out.
        self.assertNotRegex(
            asm,
            r"\.symver\s*.*,foo@libmya.so",
            msg="The base version 'libmya.so' should not be printed out",
        )

        # Build binary
        with self.binary_print(ir, "--shared") as result:
            readelf = self.readelf(result.path, "--syms", "--dynamic")

        # The unversioned symbol `foo` should exist.
        self.assert_readelf_syms(
            readelf.stdout,
            ("FUNC", "GLOBAL", "DEFAULT", "foo"),
        )

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
        with self.binary_print(ir, "--object") as result:
            output = subprocess.run(
                ["file", result.path],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue("relocatable" in output.stdout)

    def subtest_dyn_option(
        self,
        mode: str,
        shared_option: typing.Optional[str],
        pie: bool,
        shared: bool,
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
        extra_args = ["--shared"]
        if shared_option:
            extra_args.append(shared_option)

        with self.binary_print(ir, *extra_args) as result:
            output = result.completed_process.stdout

            if pie:
                self.assertIn(" -pie", output)
            else:
                self.assertNotIn(" -pie", output)

            if shared:
                self.assertIn("-shared", output)
            else:
                self.assertNotIn("-shared", output)

            self.assertTrue(result.path.exists())

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
            ("SHARED", None, False, True),
            ("PIE", "yes", False, True),
            ("PIE", "no", True, False),
            ("PIE", "auto", True, False),
        )

        for subtest in subtests:
            with self.subTest(subtest=subtest):
                self.subtest_dyn_option(*subtest)

    def subtest_dynamic_entries(
        self, sym_init: typing.Optional[str], sym_fini: typing.Optional[str]
    ):
        """
        Test that DT_INIT and DT_FINI entries are recreated
        """
        # Build a GTIRB module with DT_INIT/DT_FINI entries.
        ir, module = gth.create_test_module(
            gtirb.Module.FileFormat.ELF,
            gtirb.Module.ISA.X64,
            ["DYN", "PIE"],
        )

        # Add a .dynamic section (which gtirb-pprinter uses for detecting
        # static vs. dynamic binaries)
        gth.add_section(module, ".dynamic")

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
            if sym_name is None:
                continue
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

        module.aux_data["libraries"].data.extend(["libc.so"])

        # Add DT_INIT and DT_FINI entries
        module.aux_data["elfDynamicInit"] = gtirb.AuxData(
            type_name="UUID", data=code_blocks[".init"].uuid
        )
        module.aux_data["elfDynamicFini"] = gtirb.AuxData(
            type_name="UUID", data=code_blocks[".fini"].uuid
        )

        # Build binary
        with self.binary_print(ir) as result:
            readelf = self.readelf(result.path, "--syms", "--dynamic")

        # Verify readelf output
        for (sym, tag) in ((sym_init, "INIT"), (sym_fini, "FINI")):
            # Find the tag
            pattern = r"0x[0-9a-f]+\s+\(" + tag + r"\)\s+(0x[0-9a-f]+)"
            dt_match = self.assertRegexMatch(readelf.stdout, pattern)

            if sym_name:
                # Find the symbol
                sym_addr = self.assert_readelf_syms(
                    readelf.stdout, ("FUNC", "LOCAL", "DEFAULT", sym)
                )[0]

                # The symbol and the DT entry should have the same address
                self.assertEqual(int(sym_addr, 16), int(dt_match.group(1), 16))

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
            # No symbols
            (None, None),
        )

        for subtest in subtests:
            with self.subTest(subtest=subtest):
                self.subtest_dynamic_entries(*subtest)

    def test_export_dynamic(self):
        """
        Test that we pass -Wl,--export-dynamic when all
        global visible symbols are in .dynsym.
        """

        ir, module = gth.create_test_module(
            gtirb.Module.FileFormat.ELF,
            gtirb.Module.ISA.X64,
            ["DYN", "PIE"],
        )

        # Add a .dynamic section (which gtirb-pprinter uses for detecting
        # static vs. dynamic binaries)
        gth.add_section(module, ".dynamic")

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
        (section, section_bi) = gth.add_section(
            module, ".text", address=0x10000, flags=section_flags
        )
        # Add global exported symbols
        for index, symbol_name in enumerate(
            ["_start", "f2_symbol", "f3_symbol"]
        ):
            block = gth.add_code_block(section_bi, code_bytes, {})
            symbol = gth.add_symbol(module, symbol_name, block)
            module.aux_data["elfSymbolInfo"].data[symbol.uuid] = (
                0,
                "FUNC",
                "GLOBAL",
                "DEFAULT",
                0,
            )
            module.aux_data["elfSymbolTabIdxInfo"].data[symbol.uuid] = [
                (".symtab", index),
                (".dynsym", index),
            ]

        # Add global hidden non exported symbols
        for index, symbol_name in enumerate(
            ["f4_symbol", "f5_symbol"], start=3
        ):
            block = gth.add_code_block(section_bi, code_bytes, {})

            symbol = gth.add_symbol(module, symbol_name, block)
            module.aux_data["elfSymbolInfo"].data[symbol.uuid] = (
                0,
                "FUNC",
                "GLOBAL",
                "HIDDEN",
                0,
            )
            module.aux_data["elfSymbolTabIdxInfo"].data[symbol.uuid] = [
                (".symtab", index)
            ]

        module.aux_data["libraries"].data.extend(["libc.so"])

        # Build binary
        with self.binary_print(ir) as result:
            dynsym = self.readelf(result.path, "--dyn-syms")
            symtab = self.readelf(result.path, "--syms")

            # All the symbols in dynsym have been exported
            self.assert_readelf_syms(
                dynsym.stdout,
                ("FUNC", "GLOBAL", "DEFAULT", "_start"),
                ("FUNC", "GLOBAL", "DEFAULT", "f2_symbol"),
                ("FUNC", "GLOBAL", "DEFAULT", "f3_symbol"),
            )
            # The hidden global are not exported
            self.assertNotIn("f4_symbol", dynsym.stdout)
            self.assertNotIn("f5_symbol", dynsym.stdout)
            # The hidden global have been transformed to local
            self.assert_readelf_syms(
                symtab.stdout,
                ("FUNC", "LOCAL", "DEFAULT", "f4_symbol"),
                ("FUNC", "LOCAL", "DEFAULT", "f5_symbol"),
            )

    def subtest_elf_stack_properties(self, stack_size: int, stack_exec: bool):
        """
        Test generating `-Wl,-z,stack-size` and `-z,-execstack`
        """
        ir, module, _ = self.build_basic_ir()

        module.aux_data["elfStackSize"] = gtirb.AuxData(
            type_name="uint64_t", data=stack_size
        )
        module.aux_data["elfStackExec"] = gtirb.AuxData(
            type_name="bool", data=stack_exec
        )

        with self.binary_print(ir) as result:
            segments = self.readelf(result.path, "--segments", "--wide")
            match = self.assertRegexMatch(
                segments.stdout,
                # Type,Offset,VirtAddr,PhysAddr,FileSize,MemSize,Flg,Align
                r"GNU_STACK\s+(?:0x0+\s+){4}(0x[\da-f]+)\s+(R?W?E?)\s+"
                r"0x[\da-f]+",
            )

            self.assertEqual(int(match.group(1), 16), stack_size)
            self.assertEqual(match.group(2), "RWE" if stack_exec else "RW")

    def test_elf_stack_properties(self):
        """
        Set up subtests ELF stack properties
        """
        subtests = (
            # Size, Exec?
            (0x200000, True),
            (0x400000, False),
        )

        for stack_size, stack_exec in subtests:
            with self.subTest(stack_size=stack_size, stack_exec=stack_exec):
                self.subtest_elf_stack_properties(stack_size, stack_exec)

    def test_dummyso_arm(self):
        """
        Test printing a simple ARM GTIRB with --dummy-so.
        """
        ir, module = gth.create_test_module(
            gtirb.Module.FileFormat.ELF,
            gtirb.Module.ISA.ARM,
            ["DYN", "PIE"],
        )
        text_section, text_bi = gth.add_text_section(module)

        gth.add_section(module, ".dynamic")

        proxy_a = gth.add_proxy_block(module)
        symbol_a = gth.add_symbol(module, "a", proxy_a)
        se_a = gtirb.SymAddrConst(
            0, symbol_a, {gtirb.SymbolicExpression.Attribute.PLT}
        )

        cb = gth.add_code_block(
            text_bi,
            b"\x00\x00\x00\xeb"  # bl  a@plt
            b"\x00\x00\xa0\xe3"  # mov r0, #0
            b"\x01\x70\xa0\xe3"  # mov r7, #1
            b"\x00\x00\x00\xef",  # svc 0
            {0: se_a},
        )
        symbol_start = gth.add_symbol(module, "_start", cb)

        module.aux_data["libraries"].data.extend(["libmya.so"])

        module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        module.aux_data["elfSymbolInfo"].data[symbol_a.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )

        with self.binary_print(
            ir, "--dummy-so", "yes", "--use-gcc", "arm-linux-gnueabihf-gcc"
        ) as result:
            self.assert_readelf_syms(
                result.path,
                ("FUNC", "GLOBAL", "DEFAULT", "a"),
            )

    def subtest_dummyso_x86_32(self, legacy: bool, obj: bool):
        """
        Test printing a simple x86-32 GTIRB with --dummy-so.

        If `legacy` is enabled, the `__x86.get_pc_thunk.bx` symbol is
        constructed as if ddisasm considered it to be `abi_intrinsic`.

        If `obj` is enabled, `--object` is passed to the binary printer to
        test printing object files.
        """
        ir, module = gth.create_test_module(
            gtirb.Module.FileFormat.ELF,
            gtirb.Module.ISA.IA32,
            ["DYN", "PIE"],
        )
        text_section, text_bi = gth.add_text_section(module)

        gth.add_section(module, ".dynamic")

        thunk_cb = gth.add_code_block(
            text_bi, b"\x8b\x1c\x24" b"\xc3"  # mov EBX, DWORD PTR [ESP]  # ret
        )

        thunk_name = "__x86.get_pc_thunk.bx"
        if legacy:
            symbol_get_pc_thunk = gth.add_symbol(
                module, thunk_name + "_copy", thunk_cb
            )
            proxy_thunk = gth.add_proxy_block(module)
            symbol_thunk_proxy = gth.add_symbol(
                module, thunk_name, proxy_thunk
            )
            module.aux_data["symbolForwarding"].data[
                symbol_get_pc_thunk.uuid
            ] = symbol_thunk_proxy
        else:
            symbol_get_pc_thunk = gth.add_symbol(module, thunk_name, thunk_cb)
        se_get_pc_thunk = gtirb.SymAddrConst(0, symbol_get_pc_thunk)

        proxy_a = gth.add_proxy_block(module)
        symbol_a = gth.add_symbol(module, "a", proxy_a)
        se_a = gtirb.SymAddrConst(
            0, symbol_a, {gtirb.SymbolicExpression.Attribute.PLT}
        )

        cb = gth.add_code_block(
            text_bi,
            b"\xe8\x00\x00\x00\x00"  # calll  __x86.get_pc_thunk.bx
            b"\xe8\x00\x00\x00\x00"  # calll  a@plt
            b"\xb8\x01\x00\x00\x00"  # movl   $1,%eax
            b"\x31\xdb"  # xor    $ebx,%ebx
            b"\xcd\x80",  # int    $0x80
            {1: se_get_pc_thunk, 5: se_a},
        )
        symbol_start = gth.add_symbol(module, "_start", cb)

        module.aux_data["libraries"].data.extend(["libmya.so"])

        module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        module.aux_data["elfSymbolInfo"].data[symbol_a.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "DEFAULT",
            0,
        )
        module.aux_data["elfSymbolInfo"].data[symbol_get_pc_thunk.uuid] = (
            0,
            "FUNC",
            "GLOBAL",
            "HIDDEN",
            0,
        )

        # Configure _start as un-exported to prevent the binary-printer from
        # generating --export-dynamic, which results in unexpected symbol
        # binding/visibility for __x86.get_pc_thunk.bx. See gtirb-pprinter#227
        module.aux_data["elfSymbolTabIdxInfo"].data[symbol_start.uuid] = [
            (".symtab", 0)
        ]

        extra_args = []
        if obj:
            extra_args.append("--object")

        with self.binary_print(ir, "--dummy-so", "yes", *extra_args) as result:
            readelf_dynsyms = self.readelf(result.path, "--dyn-syms").stdout
            readelf_symbols = self.readelf(result.path, "--symbols").stdout

            if not obj:
                self.assert_readelf_syms(
                    readelf_dynsyms,
                    ("FUNC", "GLOBAL", "DEFAULT", "a"),
                )

            self.assertNotIn("__x86.get_pc_thunk.bx", readelf_dynsyms)
            self.assert_readelf_syms(
                readelf_symbols,
                ("FUNC", "GLOBAL", "HIDDEN", "__x86.get_pc_thunk.bx"),
            )

    def test_dummyso_x86_32(self):
        """
        Set up subtests for x86-32 GTIRB with --dummy-so.
        """
        cases = (
            # legacy, object
            (True, False),
            (False, False),
            (False, True),
            (True, True),
        )

        for legacy, obj in cases:
            with self.subTest(legacy=legacy, obj=obj):
                self.subtest_dummyso_x86_32(legacy, obj)
