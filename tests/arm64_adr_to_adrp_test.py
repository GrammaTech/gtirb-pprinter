import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm64AdrpSubstitutionTest(PPrinterTest):
    def test_adr_substitution(self):
        """
        In some cases, the assembler will substitute an adr instruction where
        the assembly contained an adrp instruction. If we apply a :got:
        attribute to that symbolic expression, the assembler won't assemble it.
        In that case, we must reverse the adrp -> adr substitution.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ARM64,
        )
        s, bi = add_text_section(m)

        insn_bytes = b"\x20\x00\x00\x10"  # adr x0, label
        add_code_block(bi, insn_bytes)

        insn_bytes = b"\x1f\x20\x03\xd5"  # nop
        block_nop = add_code_block(bi, insn_bytes)

        sym = gtirb.symbol.Symbol(
            "__stack_chk_guard", payload=block_nop, module=m
        )
        sym_expr = gtirb.symbolicexpression.SymAddrConst(
            0,
            sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.GotRef
            ],
        )
        bi.symbolic_expressions[0] = sym_expr

        asm = run_asm_pprinter(ir)

        # Verify that the instruction is printed correctly.
        self.assertIn("adrp x0, :got:__stack_chk_guard", asm)

        # Verify that a comment is added
        self.assertIn("Instruction substituted", asm)
