import gtirb
from gtirb_helpers import (
    create_test_module,
    add_code_block,
    add_text_section,
    add_section,
    add_function,
    add_elf_symbol_info,
    add_symbol,
)
from pprinter_helpers import run_asm_pprinter, PPrinterTest, asm_lines


class PrintingPolicyTests(PPrinterTest):
    def test_keep_function(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        add_function(m, "_start", add_code_block(bi, b"\xC3"))

        asm = run_asm_pprinter(
            ir, ["--syntax", "intel", "--policy", "dynamic"]
        )
        self.assertNotContains(
            asm_lines(asm), ["_start:", "ret", ".size _start, . - _start"]
        )
        asm = run_asm_pprinter(
            ir, ["--keep-function", "_start", "--syntax", "intel"]
        )
        self.assertContains(
            asm_lines(asm), ["_start:", "ret", ".size _start, . - _start"]
        )

    def test_skip_function_alias(self):
        """
        Check that skip function works with
        function aliases too.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        code = add_code_block(bi, b"\xC3")
        add_function(m, "foo", code)

        alias_sym = add_symbol(m, "foo_alias", code)
        add_elf_symbol_info(m, alias_sym, 0, "FUNC")

        function_lines = [
            "foo_alias:",
            "retq",
            ".size foo, . - foo",
            ".size foo_alias, . - foo_alias",
        ]
        asm = run_asm_pprinter(ir)
        self.assertContains(asm_lines(asm), function_lines)
        asm = run_asm_pprinter(ir, ["--skip-function", "foo_alias"])
        self.assertNotContains(asm_lines(asm), function_lines)
