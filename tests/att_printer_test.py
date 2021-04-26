import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class ATTInstructionsTest(PPrinterTest):
    def test_avx512_att(self):
        # This test ensures that we do not regress on the following issue:
        # git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/330
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        # vpaddq %zmm2, %zmm3, %zmm1 {%k1}{z}
        add_code_block(bi, b"\x62\xF1\xE5\xC9\xD4\xCA")

        # We're specifically trying to see if there is a space between {%kN}
        # operands and the {z} mask.
        asm = run_asm_pprinter(ir, ["--syntax=att"])
        self.assertIn("{%k1}{z}", asm)
