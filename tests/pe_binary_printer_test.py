import unittest

import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import (
    PPrinterTest,
    can_mock_binaries,
    interesting_lines,
    run_binary_pprinter_mock,
)


@unittest.skipUnless(can_mock_binaries(), "cannot mock binaries")
class WindowsBinaryPrinterTests(PPrinterTest):
    def test_windows_subsystem_gui(self):
        # This tests the changes in MR 346.
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_GUI"],
        )
        _, bi = add_text_section(m)
        block = add_code_block(bi, b"\xC3")
        m.entry_point = block

        tools = list(run_binary_pprinter_mock(ir))
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "ml64")
        self.assertIn("/SUBSYSTEM:windows", tools[0].args)

    def test_windows_subsystem_console(self):
        # This tests the changes in MR 346.
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
            binary_type=["EXEC", "EXE", "WINDOWS_CUI"],
        )
        _, bi = add_text_section(m)
        block = add_code_block(bi, b"\xC3")
        m.entry_point = block

        tools = list(run_binary_pprinter_mock(ir))
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "ml64")
        self.assertIn("/SUBSYSTEM:console", tools[0].args)

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
        self.assertEqual(tools[0].name, "ml64")
        self.assertIn("/DLL", tools[0].args)

    def test_windows_defs(self):
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
