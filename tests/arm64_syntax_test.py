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
