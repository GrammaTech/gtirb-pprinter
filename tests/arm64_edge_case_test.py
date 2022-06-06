import gtirb

from gtirb_helpers import (
    add_code_block,
    add_data_block,
    add_data_section,
    add_elf_symbol_info,
    add_symbol_forwarding,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class Arm64EdgeCases(PPrinterTest):
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

    def test_local_got_reference(self):
        """
        .got references are not generated correctly unless they refer to
        global symbols - we must rewrite symbols referenced in the .got as
        global.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.ARM64,
        )
        s, bi = add_text_section(m)

        insn_bytes = b"\x20\x00\x00\xb0"  # adr x0, label
        add_code_block(bi, insn_bytes)

        # Add .got section
        _, bi_data = add_data_section(m)
        got_data = add_data_block(bi_data, b"\xff\xff\xff\xff")

        got_sym = gtirb.symbol.Symbol(
            "got_my_local", payload=got_data, module=m
        )

        # Add target data section
        _, bi_data = add_data_section(m)
        block_data = add_data_block(bi_data, b"\xff\xff\xff\xff")

        sym = gtirb.symbol.Symbol("my_local", payload=block_data, module=m)

        add_symbol_forwarding(m, got_sym, sym)
        add_elf_symbol_info(
            m,
            sym,
            block_data.size,
            "OBJECT",
            binding="LOCAL",
            visibility="DEFAULT",
        )

        sym_expr = gtirb.symbolicexpression.SymAddrConst(
            0,
            got_sym,
            attributes=[
                gtirb.symbolicexpression.SymbolicExpression.Attribute.GotRef
            ],
        )
        bi.symbolic_expressions[0] = sym_expr

        asm = run_asm_pprinter(ir)

        # Verify that the instruction is printed correctly.
        self.assertIn("adrp x0, :got:my_local", asm)

        # Verify that the symbol is printed with global and hidden attributes.
        self.assertIn(".type my_local, @object", asm)
        self.assertIn(".globl my_local", asm)
        self.assertIn(".hidden my_local", asm)
        self.assertIn("my_local:", asm)
