import gtirb

from gtirb_test_helpers import (
    add_code_block,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import (
    run_asm_pprinter,
    run_asm_pprinter_with_output,
    PPrinterTest,
)


class Mips32SyntaxTest(PPrinterTest):
    def test_got_page_ofst(self):
        """
        Test printing got_page and got_ofst attributes
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.MIPS32,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        s, bi = add_text_section(m)

        insn_bytes = (
            b"\x00\x00\x99\x8f"  # lw $t9,%got_page(fun)($gp)
            b"\x00\x00\x39\x27"  # addiu $t9,$t9,%got_ofst(fun)
        )
        add_code_block(bi, insn_bytes)

        insn_bytes = b"\x00\x00\x00\x00"  # nop
        block_nop = add_code_block(bi, insn_bytes)

        sym = gtirb.symbol.Symbol("fun", payload=block_nop, module=m)
        sym_expr1 = gtirb.symbolicexpression.SymAddrConst(
            0,
            sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.GOT,
                gtirb.symbolicexpression.SymbolicExpression.Attribute.PAGE,
            ],
        )
        sym_expr2 = gtirb.symbolicexpression.SymAddrConst(
            0,
            sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.GOT,
                gtirb.symbolicexpression.SymbolicExpression.Attribute.OFST,
            ],
        )

        bi.symbolic_expressions[0] = sym_expr1
        bi.symbolic_expressions[4] = sym_expr2

        asm = run_asm_pprinter(ir)

        # Verify that the instruction is printed correctly.
        self.assertIn("lw $t9,%got_page(fun)($gp)", asm)
        self.assertIn("addiu $t9,$t9,%got_ofst(fun)", asm)

    def test_unsupported_symexpr_attribute_warning(self):
        """
        Test printing unsupported symbolic expression attributes
        generates a warning.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.MIPS32,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        s, bi = add_text_section(m)

        insn_bytes = b"\x00\x00\x99\x8f"  # lw $t9,%got(fun)($gp)
        add_code_block(bi, insn_bytes)

        insn_bytes = b"\x00\x00\x00\x00"  # nop
        block_nop = add_code_block(bi, insn_bytes)

        sym = gtirb.symbol.Symbol("fun", payload=block_nop, module=m)
        sym_expr = gtirb.symbolicexpression.SymAddrConst(
            0,
            sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.GOT,
                gtirb.symbolicexpression.SymbolicExpression.Attribute.PREL31,
            ],
        )

        bi.symbolic_expressions[0] = sym_expr

        asm, output = run_asm_pprinter_with_output(ir)

        # Verify that the instruction is printed correctly.
        self.assertIn("lw $t9,%got(fun)($gp)", asm)

        self.assertIn(
            "Ignoring symbolic expression attributes with no known MIPS "
            "representation:",
            output,
        )
