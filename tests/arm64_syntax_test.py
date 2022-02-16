import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm64InstructionsTest(PPrinterTest):
    def test_unpack_instructions(self):
        """
        Test printing various instructions
        """
        instructions = [
            (b"\x00\x08\x80\xD2", "mov x0,#64"),
            (b"\xE8\x0E\x04\x0E", "dup v8.2s,w23"),
            (b"\xC7\x04\x02\x4E", "dup v7.8h,v6.h[0]"),
            (b"\x00\x00\x01\x4E", "tbl v0.16b,{v0.16b},v1.16b"),
            (b"\x47\x90\x00\x0D", "st1 {v7.s}[1],[x2]"),
            (b"\x9D\x0E\x9E\x0D", "st1 {v29.b}[3],[x20],lr"),
            # TODO: capstone bug, see
            # https://github.com/capstone-engine/capstone/issues/1842
            # (b"\xDD\x9F\x2D\x05", "splice z29.b,p7,{z30.b,z31.b}"),
            # (b"\xFD\x9F\x2C\x05", "splice z29.b,p7,z30.b,z31.b"),
            # TODO: capstone bug, see
            # https://github.com/capstone-engine/capstone/issues/1843
            # (b"\x40\x1E\xB2\x4E", "mov v0.16b, v18.16b"),
        ]

        for insn_bytes, insn_str in instructions:
            with self.subTest(instruction=insn_str):
                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.ARM64,
                )
                s, bi = add_text_section(m)

                add_code_block(bi, insn_bytes)

                asm = run_asm_pprinter(ir)
                self.assertIn(insn_str, asm)
