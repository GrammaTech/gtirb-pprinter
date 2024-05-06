import gtirb
from gtirb_helpers import (
    add_data_block,
    add_symbol,
    add_elf_symbol_info,
    create_test_module,
    add_code_block,
    add_text_section,
    add_section,
    add_function,
)
from pprinter_helpers import run_asm_pprinter, PPrinterTest, asm_lines
import uuid


class FunctionTests(PPrinterTest):
    def test_function_with_data_block(self):
        """
        Check that the function size is printed at the end, after the data
        block that belongs to the function.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        func_uuid = add_function(m, "foo", add_code_block(bi, b"\xC3"))
        data_block = add_data_block(bi, b"\xCC")
        m.aux_data["functionBlocks"].data[func_uuid].add(data_block)

        asm = run_asm_pprinter(ir)

        self.assertContains(
            asm_lines(asm),
            ["foo:", "retq", ".byte 0xcc", ".size foo, . - foo"],
        )

    def test_masm_function(self):
        """
        Check that ENDP is printed at the end of a function correctly.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE,
            isa=gtirb.Module.ISA.X64,
        )
        _, bi = add_text_section(m)
        func_uuid = add_function(m, "foo", add_code_block(bi, b"\xC3"))

        asm = run_asm_pprinter(ir)

        self.assertContains(
            asm_lines(asm),
            ["foo PROC", "ret", "foo ENDP"],
        )

        data_block = add_data_block(bi, b"\xCC")
        m.aux_data["functionBlocks"].data[func_uuid].add(data_block)

        asm = run_asm_pprinter(ir)
        self.assertContains(
            asm_lines(asm),
            ["foo PROC", "ret", "BYTE 0ccH", "foo ENDP"],
        )

    def test_function_with_alias(self):
        """
        Check that a function alias gets a size directive too. In ELF, a Symbol
        at the same location is only alias if it is of type FUNC or GNU_IFUNC
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        code_block = add_code_block(bi, b"\xC3")
        add_function(m, "foo", code_block)
        # add aliases
        alias_sym = add_symbol(m, "foo_alias", code_block)
        add_elf_symbol_info(m, alias_sym, 0, "FUNC")
        ifunc_alias_sym = add_symbol(m, "ifunc_foo_alias", code_block)
        add_elf_symbol_info(m, ifunc_alias_sym, 0, "GNU_IFUNC")
        # This is not an alias because it is not of type FUNC
        add_symbol(m, "foo_false_alias", code_block)

        asm = run_asm_pprinter(ir)

        self.assertContains(asm_lines(asm), [".size foo, . - foo"])
        self.assertContains(asm_lines(asm), [".size foo_alias, . - foo_alias"])
        self.assertContains(
            asm_lines(asm), [".size ifunc_foo_alias, . - ifunc_foo_alias"]
        )
        self.assertNotContains(
            asm_lines(asm), [".size foo_false_alias, . - foo_false_alias"]
        )

    def test_anonymous_function(self):
        """
        Check that a function without name does not cause problems
        and it is not skipped.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            binary_type=["DYN"],
        )
        _, _ = add_section(m, ".dynamic")
        _, bi = add_text_section(m)

        # Create normal function
        code_block = add_code_block(bi, b"\xC3")
        add_function(m, "foo", code_block)

        # Create anonymous function
        code_block2 = add_code_block(bi, b"\xCC")
        func_uuid = uuid.uuid4()
        m.aux_data["functionEntries"].data[func_uuid] = [code_block2]
        m.aux_data["functionBlocks"].data[func_uuid] = [code_block2]

        # Create normal function
        code_block3 = add_code_block(bi, b"\xC3")
        add_function(m, "foo3", code_block3)

        asm = run_asm_pprinter(ir)
        # there is a block outside the function
        self.assertContains(
            asm_lines(asm), ["foo:", "retq", ".size foo, . - foo", "int $3"]
        )

        asm = run_asm_pprinter(ir, ["--skip-function", "foo", "foo3"])
        # even if we skip foo and foo3, there code in between is left
        self.assertNotContains(asm_lines(asm), ["retq"])
        self.assertContains(asm_lines(asm), ["int $3"])
