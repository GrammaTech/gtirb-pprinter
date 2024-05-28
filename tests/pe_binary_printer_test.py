import os
import platform
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

import gtirb

from gtirb_helpers import (
    add_byte_block,
    add_code_block,
    add_section,
    add_symbol,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import (
    PPrinterTest,
    BinaryPPrinterTest,
    can_mock_binaries,
    interesting_lines,
    run_binary_pprinter_mock,
    run_asm_pprinter,
    asm_lines,
    run_binary_pprinter_mock_out,
    vs_arch,
    vsenv_run,
)

TEST_DIR = os.path.abspath(os.path.dirname(__file__))
FAKEBIN_LLVM = os.path.join(TEST_DIR, "fakebin_llvm")


@unittest.skipUnless(can_mock_binaries(), "cannot mock binaries")
class WindowsBinaryPrinterTests(PPrinterTest):
    def test_windows_subsystem(self):
        """
        Test that the binary-printer generates the correct "/SUBSYSTEM" flag
        """
        cases = [
            ("WINDOWS_GUI", "/SUBSYSTEM:windows"),
            ("WINDOWS_CUI", "/SUBSYSTEM:console"),
        ]
        for subsystem_type, subsystem_arg in cases:
            with self.subTest(subsystem=subsystem_type):
                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.PE,
                    isa=gtirb.Module.ISA.X64,
                    binary_type=["EXEC", "EXE", subsystem_type],
                )
                _, bi = add_text_section(m)
                block = add_code_block(bi, b"\xC3")
                m.entry_point = block

                tools = list(run_binary_pprinter_mock(ir))
                self.assertEqual(len(tools), 1)
                self.assertEqual(tools[0].name, "ml64.exe")
                self.assertIn(subsystem_arg, tools[0].args)

    def test_windows_dll(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "DLL", "WINDOWS_CUI"],
        )
        _, bi = add_text_section(m)
        add_code_block(bi, b"\xC3")

        tools = list(run_binary_pprinter_mock(ir))
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "ml64.exe")
        self.assertIn("/DLL", tools[0].args)

    def test_windows_defs(self):
        """
        Test that the PE binary-printer uses lib.exe to generate import libs
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_CUI"],
        )
        m.aux_data["peImportEntries"].data.append(
            (0, -1, "GetMessageW", "USER32.DLL")
        )

        for tool in run_binary_pprinter_mock(ir):
            if tool.name == "lib.exe":
                def_arg = next(
                    (arg for arg in tool.args if arg.startswith("/DEF:")), None
                )
                self.assertIsNotNone(def_arg, "no /DEF in lib invocation")
                self.assertIn("/MACHINE:X64", tool.args)

                with open(def_arg[5:], "r") as f:
                    lines = interesting_lines(f.read())
                    self.assertEqual(
                        lines,
                        ['LIBRARY "USER32.DLL"', "EXPORTS", "GetMessageW"],
                    )
                break
        else:
            self.fail("did not see a lib.exe execution")

    def test_windows_defs_with_llvm(self):
        """
        Check that:
        - we find the llvm installation directory
          using our fake llvm-config
        - the directory gets added to our path
        - we find llvm-dlltool
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_CUI"],
        )
        m.aux_data["peImportEntries"].data.append(
            (0, -1, "GetMessageW", "USER32.DLL")
        )

        expected_calls = ["llvm-config", "llvm-dlltool", "ml64.exe"]
        for tool in run_binary_pprinter_mock(ir, fakebin_dir=FAKEBIN_LLVM):
            if tool.name in expected_calls:
                expected_calls.remove(tool.name)
            if len(expected_calls) == 0:
                break
        else:
            self.fail(
                "did not see the following executions: "
                + ",".join(expected_calls)
            )


class WindowsBinaryPrinterTests_NoMock(BinaryPPrinterTest):
    def test_windows_includelib(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_CUI"],
        )

        _, bi = add_text_section(m)
        m.aux_data["libraries"].data.append(("WINSPOOL.DRV"))
        m.aux_data["libraries"].data.append(("USER32.DLL"))

        asm = run_asm_pprinter(ir)

        self.assertContains(asm_lines(asm), ["INCLUDELIB WINSPOOL.lib"])
        self.assertContains(asm_lines(asm), ["INCLUDELIB USER32.lib"])

        self.assertNotContains(asm_lines(asm), ["INCLUDELIB WINSPOOL.DRV"])
        self.assertNotContains(asm_lines(asm), ["INCLUDELIB USER32.DLL"])

    def test_windows_dll_exports(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.IA32,
            binary_type=["EXEC", "DLL", "WINDOWS_CUI"],
        )
        _, bi = add_text_section(m, 0x4000A8)
        block = add_code_block(bi, b"\xC3")
        sym = add_symbol(m, "__glutInitWithExit", block)

        m.aux_data["peExportedSymbols"].data.append(sym.uuid)
        func_uuid = uuid.uuid4()
        m.aux_data["functionNames"].data[func_uuid] = sym
        m.aux_data["functionEntries"].data[func_uuid] = [block]
        m.aux_data["functionBlocks"].data[func_uuid] = [block]

        asm = run_asm_pprinter(ir)

        self.assertContains(
            asm_lines(asm), ["___glutInitWithExit PROC EXPORT"]
        )

    def make_pe_resource_data(self) -> gtirb.IR:

        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_GUI"],
        )

        _, bi = add_section(m, ".text")
        entry = add_code_block(bi, b"\xC3")
        m.entry_point = entry

        resource_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x02\x00\x06\x00\x00\x00 \x00\x00\x80\
        \x18\x00\x00\x008\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x01\x00\x07\x00\x00\x00P\x00\
        \x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x01\x00\x01\x00\x00\x00h\x00\x00\x80\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\t\x04\
        \x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x01\x00\t\x04\x00\x00\x90\x00\x00\x00\
        \xa0`\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \xe8`\x00\x00}\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00T\x00e\x00s\
        \x00t\x00 \x00r\x00e\x00s\x00o\x00u\x00r\x00c\x00e\x00 \x00s\
        \x00t\x00r\x00i\x00n\x00g\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        <?xml version='1.0' encoding='UTF-8' standalone='yes'?>\
        \r\n<assembly xmlns='urn:schemas-microsoft-com:asm.v1\
        ' manifestVersion='1.0'>\r\n  \
        <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n\
            <security>\r\n      <requestedPrivileges>\r\n        \
            <requestedExecutionLevel level='asInvoker' uiAccess='false' />\r\n\
          </requestedPrivileges>\r\n    </security>\r\n  </trustInfo>\
                 \r\n</assembly>\r\n\x00\x00\x00')"

        _, bi = add_section(m, ".rsrc")
        _ = add_byte_block(bi, gtirb.block.DataBlock, resource_data)
        off1 = gtirb.Offset(bi, 0)
        off2 = gtirb.Offset(bi, 72)
        entry1 = (
            [
                72,
                0,
                0,
                0,
                32,
                0,
                0,
                0,
                255,
                255,
                6,
                0,
                255,
                255,
                7,
                0,
                0,
                0,
                0,
                0,
                48,
                16,
                9,
                4,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            off1,
            72,
        )
        entry2 = (
            [
                125,
                1,
                0,
                0,
                32,
                0,
                0,
                0,
                255,
                255,
                24,
                0,
                255,
                255,
                1,
                0,
                0,
                0,
                0,
                0,
                48,
                16,
                9,
                4,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            off2,
            381,
        )
        m.aux_data["peResources"] = gtirb.AuxData(
            [entry1, entry2],
            "sequence<tuple<sequence<uint8_t>,Offset,uint64_t>>",
        )
        return ir

    def test_windows_pe_resource_data(self):
        # checks that the IR gets turned into a binary
        ir = self.make_pe_resource_data()
        output = run_binary_pprinter_mock_out(
            ir, [], check_output=True
        ).stdout.decode(sys.stdout.encoding)
        self.assertTrue(output)

    @unittest.skipUnless(can_mock_binaries(), "cannot mock binaries")
    def test_windows_pe_resource_data_mock(self):
        # checks that a resource file is compiled from the resource data
        ir = self.make_pe_resource_data()
        has_resource_file = False
        for output in run_binary_pprinter_mock(ir):
            if any(".res" in arg for arg in output.args):
                has_resource_file = True

        self.assertTrue(has_resource_file, "did not produce resource file")

    def dumpbin(
        self, path: Path, arch: str, *args
    ) -> subprocess.CompletedProcess:
        return vsenv_run(
            ["DUMPBIN", *args, path],
            arch,
            check=True,
            capture_output=True,
            text=True,
        )

    def subtest_windows_decorated_exports(self, arch: gtirb.Module.ISA):
        """
        Test that the binary-printer successfully exports symbols
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=arch,
            binary_type=["EXEC", "DLL", "WINDOWS_CUI"],
        )

        _, bi = add_text_section(m)

        exported_blocks = [
            ("Baz", gtirb.CodeBlock),
            ("_Baz", gtirb.CodeBlock),
            ("__Baz", gtirb.CodeBlock),
            ("___Baz", gtirb.CodeBlock),
            ("baz_count", gtirb.DataBlock),
            ("_baz_count", gtirb.DataBlock),
            ("__baz_count", gtirb.DataBlock),
            ("___baz_count", gtirb.DataBlock),
        ]

        for ordinal, (name, block_type) in enumerate(exported_blocks, start=1):
            block = add_byte_block(bi, block_type, b"\xC3")
            symbol = add_symbol(m, name, block)
            m.aux_data["peExportEntries"].data.append((0, ordinal, name))
            m.aux_data["peExportedSymbols"].data.append(symbol.uuid)

        with self.binary_print(ir) as result:
            exports = self.dumpbin(result.path, vs_arch(ir), "/EXPORTS").stdout
            for ordinal, (name, _) in enumerate(exported_blocks, start=1):
                self.assertRegex(
                    exports, rf"{ordinal}\s+\d+\s+[0-9a-f]+\s+{name}"
                )

    @unittest.skipUnless(platform.system() == "Windows", "Windows-only")
    def test_windows_decorated_exports(self):
        """
        Test that the binary-printer successfully exports symbols on each arch
        """
        cases = (
            gtirb.Module.ISA.X64,
            gtirb.Module.ISA.IA32,
        )
        for arch in cases:
            with self.subTest(arch=arch):
                self.subtest_windows_decorated_exports(arch)

    def test_float_arith_fixup(self):
        """
        Test that the binary-printer successfully fixes up floating-point
        instructions with implicit register: ST(0).
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_CUI"],
        )
        _, bi = add_text_section(m)
        # dc c1: fadd ST(1),ST(0): capstone provides both operands
        # d8 c1: fadd ST(0),ST(1): capstone only provides ST(1);
        #        The first operand ST(0) is implicit.
        # de c1: faddp ST(1),ST(0): capstone only provides ST(1);
        #        The second operand ST(0) is implicit.
        code = b"\xDC\xC1\xD8\xC1\xDE\xC1"
        # dc c9: fmul ST(1),ST(0): capstone provides both operands
        # d8 c9: fmul ST(0),ST(1): capstone only provides ST(1);
        #        The first operand ST(0) is implicit.
        # de c9: fmulp ST(1),ST(0): capstone only provides ST(1);
        #        The second operand ST(0) is implicit.
        code += b"\xDC\xC9\xD8\xC9\xDE\xC9"

        # dc e9: fsub ST(1),ST(0): capstone provides both operands
        # d8 e1: fsub ST(0),ST(1): capstone provides one operand: ST(1);
        #        The first operand ST(0) is implicit.
        # d8 e9: fsubr ST(0),ST(1): capstone provides one operand: ST(1);
        #        The first operand ST(0) is implicit.
        # dc e1: fsubr ST(1),ST(0): capstone provides both operands
        # de e9: fsubp ST(1),ST(0): capstone provides one operand: ST(1);
        #        The second operand ST(0) is implicit.
        # de e1: fsubrp ST(1),ST(0): capstone provides one operand: ST(1);
        #        The second operand ST(0) is implicit.
        code += b"\xDC\xE9\xD8\xE1\xD8\xE9\xDC\xE1\xDE\xE9\xDE\xE1"

        # dc f9: fdiv ST(1),ST(0): capstone provides both operands
        # d8 f1: fdiv ST(0),ST(1): capstone provides one operand: ST(1);
        #        The first operand ST(0) is implicit.
        # d8 f9: fdivr ST(0),ST(1): capstone provides one operand: ST(1);
        #        The first operand ST(0) is implicit.
        # dc f1: fdivr ST(1),ST(0): capstone provides both operands
        # de f9: fdivp ST(1),ST(0): capstone provides one operand: ST(1);
        #        The second operand ST(0) is implicit.
        # de f1: fdivrp ST(1),ST(0): capstone provides one operand: ST(1);
        #        The second operand ST(0) is implicit.
        code += b"\xDC\xF9\xD8\xF1\xD8\xF9\xDC\xF1\xDE\xF9\xDE\xF1"

        block = add_code_block(bi, code)

        asm = run_asm_pprinter(ir)

        print(asm)

        self.assertContains(asm_lines(asm), ["fadd ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fadd ST(0),ST(1)"])
        self.assertContains(asm_lines(asm), ["faddp ST(1),ST(0)"])
        self.assertNotContains(asm_lines(asm), ["faddp ST(0),ST(1)"])

        self.assertContains(asm_lines(asm), ["fmul ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fmul ST(0),ST(1)"])
        self.assertContains(asm_lines(asm), ["fmulp ST(1),ST(0)"])
        self.assertNotContains(asm_lines(asm), ["fmulp ST(0),ST(1)"])

        self.assertContains(asm_lines(asm), ["fsub ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fsub ST(0),ST(1)"])
        self.assertContains(asm_lines(asm), ["fsubr ST(0),ST(1)"])
        self.assertContains(asm_lines(asm), ["fsubr ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fsubp ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fsubrp ST(1),ST(0)"])
        self.assertNotContains(asm_lines(asm), ["fsubp ST(0),ST(1)"])
        self.assertNotContains(asm_lines(asm), ["fsubrp ST(0),ST(1)"])

        self.assertContains(asm_lines(asm), ["fdiv ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fdiv ST(0),ST(1)"])
        self.assertContains(asm_lines(asm), ["fdivr ST(0),ST(1)"])
        self.assertContains(asm_lines(asm), ["fdivr ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fdivp ST(1),ST(0)"])
        self.assertContains(asm_lines(asm), ["fdivrp ST(1),ST(0)"])
        self.assertNotContains(asm_lines(asm), ["fdivp ST(0),ST(1)"])
        self.assertNotContains(asm_lines(asm), ["fdivrp ST(0),ST(1)"])
