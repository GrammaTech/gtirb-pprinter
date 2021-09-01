import unittest

import gtirb

from gtirb_helpers import (
    add_byte_block,
    add_code_block,
    add_section,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import (
    PPrinterTest,
    can_mock_binaries,
    interesting_lines,
    run_binary_pprinter_mock,
    run_asm_pprinter,
    asm_lines,
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
        self.assertEqual(tools[0].name, "ml64.exe")
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
        self.assertEqual(tools[0].name, "ml64.exe")
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
        self.assertEqual(tools[0].name, "ml64.exe")
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


class WindowsBinaryPrinterTests_NoMock(PPrinterTest):
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

    def test_windows_REData(self):
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

        _, bi = add_section(m, ".rscs")
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

        for output in run_binary_pprinter_mock(ir):
            print("checking output")
            # TODO: what do we need to be checking?
            self.assertIn(".res", output.args)
