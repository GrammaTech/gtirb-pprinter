import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm64InstructionsTest(PPrinterTest):
    def test_unpack_mov(self):
        """
        Test mov REG, #imm instruction
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.ARM64
        )
        s, bi = add_text_section(m)

        # mov x0, 64
        add_code_block(bi, b"\x00\x08\x80\xD2")

        asm = run_asm_pprinter(ir)
        self.assertIn("mov x0,#64", asm)
