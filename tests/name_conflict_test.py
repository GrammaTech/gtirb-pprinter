import unittest
from gtirb_helpers import (
    add_text_section,
    create_test_module,
    add_function,
    add_code_block,
)
import pprinter_helpers
import gtirb

# Does the pretty-printer need to deal with conflicts between
# reserved asm words and symbol names?
# ATT syntax: NO
# Intel syntax: YES (but not DIV)
# MASM syntax: YES (longer list)
# ARM/ARM64/Mips: Maybe? If so, it would be a different
#  set of keywords than Intel/Masm; if it ever comes up
#  we can start handling it then


def create_ir_with_name(name: str) -> gtirb.IR:
    (ir, m) = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    cb = add_code_block(bi, b"\xC3")
    add_function(m, name, cb)
    return ir


class NameConflictTest(unittest.TestCase):
    def test_di_att(self):
        ir = create_ir_with_name("di")
        asm = pprinter_helpers.run_asm_pprinter(ir, ["--syntax", "att"])
        self.assertIn("di:", asm)

    def test_di_intel(self):
        ir = create_ir_with_name("di")
        asm = pprinter_helpers.run_asm_pprinter(
            ir, ["--syntax", "intel", "--format", "raw"]
        )
        self.assertIn("di_renamed:", asm)

    def test_di_masm(self):
        ir = create_ir_with_name("di")
        asm = pprinter_helpers.run_asm_pprinter(
            ir, ["--syntax", "masm", "--format", "raw"]
        )
        self.assertIn("di_renamed:", asm)

    def test_div_intel(self):
        ir = create_ir_with_name("div")
        asm = pprinter_helpers.run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertIn("div:", asm)

    def test_div_masm(self):
        ir = create_ir_with_name("div")
        asm = pprinter_helpers.run_asm_pprinter(
            ir, ["--syntax", "masm", "--format", "raw"]
        )
        self.assertIn("div_renamed:", asm)
