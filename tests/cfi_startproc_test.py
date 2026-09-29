"""
Tests printing of `.cfi_startproc`, including the `simple` argument, which
is encoded in the cfiDirectives AuxData table as a single operand of 1.
"""

import uuid

import gtirb

from gtirb_helpers import add_code_block, add_function, add_text_section
from gtirb_helpers import create_test_module
from pprinter_helpers import PPrinterTest, asm_lines, run_asm_pprinter

NIL_UUID = uuid.UUID(int=0)


def create_ir_with_startproc(operands):
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    # ret
    cb = add_code_block(bi, b"\xc3")
    add_function(m, "fun", cb)
    m.aux_data["cfiDirectives"].data = {
        gtirb.Offset(cb, 0): [
            (".cfi_startproc", operands, NIL_UUID),
            (".cfi_def_cfa", [7, 8], NIL_UUID),
            (".cfi_offset", [16, -8], NIL_UUID),
        ],
        gtirb.Offset(cb, 1): [(".cfi_endproc", [], NIL_UUID)],
    }
    return ir


class CfiStartprocTest(PPrinterTest):
    def startproc_lines(self, operands):
        asm = run_asm_pprinter(create_ir_with_startproc(operands))
        return [
            line for line in asm_lines(asm) if line.startswith(".cfi_start")
        ]

    def test_startproc_default(self):
        for operands in ([], [0]):
            with self.subTest(operands=operands):
                self.assertEqual(
                    self.startproc_lines(operands), [".cfi_startproc"]
                )

    def test_startproc_simple(self):
        self.assertEqual(self.startproc_lines([1]), [".cfi_startproc simple"])
