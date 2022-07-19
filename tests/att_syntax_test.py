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

    def test_shift_att(self):
        """
        Prevent regression on the following:

        https://git.grammatech.com/rewriting/ddisasm/-/issues/415
        https://git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/466#note_180416
        """

        # capstone drops %cl operand from shl instructions
        instructions = [
            (b"\xD3\x65\xF8", "shll %cl,-8(%rbp)"),
            (b"\x48\xD3\x24\x24", "shlq %cl,(%rsp)"),
            (b"\x48\xD3\x6D\xB8", "shrq %cl,-72(%rbp)"),
            (b"\x48\xD3\xBD\x78\xFF\xFF\xFF", "sarq %cl,-136(%rbp)"),
        ]

        for insn_bytes, insn_str in instructions:
            with self.subTest(instruction=insn_str):

                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.X64,
                )
                s, bi = add_text_section(m)

                add_code_block(bi, insn_bytes)

                # specifically, ensure the `%cl` operand is printed
                asm = run_asm_pprinter(ir, ["--syntax=att"])
                self.assertIn(insn_str, asm)
