import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class IntelInstructionsTest(PPrinterTest):
    def test_unpack_dd(self):
        # This test ensures that we do not regress on the following issue:
        # git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/439
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        # vpgatherdd ymm1,DWORD PTR [r8+ymm5*4],ymm6
        add_code_block(bi, b"\xC4\xC2\x4D\x90\x0c\xA8")

        # We're specifically trying to see if the middle operand is a
        # DWORD PTR or a YMMWORD PTR.
        asm = run_asm_pprinter(ir, ["--syntax=intel"])
        self.assertIn("DWORD PTR", asm)

    def test_unpack_qd(self):
        # This test ensures that we do not regress on the following issue:
        # git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/439
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        # vpgatherqd xmm1,DWORD PTR [r8+xmm5*4],xmm6
        add_code_block(bi, b"\xC4\xC2\x49\x91\x0c\xa8")

        # We're specifically trying to see if the middle operand is a
        # DWORD PTR or a YMMWORD PTR.
        asm = run_asm_pprinter(ir, ["--syntax=intel"])
        self.assertIn("DWORD PTR", asm)

    def test_unpack_dq(self):
        # This test ensures that we do not regress on the following issue:
        # git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/439
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        # vpgatherdq ymm7,QWORD PTR [rcx+xmm4*1],xmm8
        add_code_block(bi, b"\xC4\xE2\xBD\x90\x3c\x21")

        # We're specifically trying to see if the middle operand is a
        # QWORD PTR or a YMMWORD PTR.
        asm = run_asm_pprinter(ir, ["--syntax=intel"])
        self.assertIn("QWORD PTR", asm)

    def test_unpack_qq(self):
        # This test ensures that we do not regress on the following issue:
        # git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/439
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        # vpgatherqq ymm12,QWORD PTR [r13+ymm10*1],xmm11
        add_code_block(bi, b"\xC4\x02\xA5\x91\x64\x15\x00")

        # We're specifically trying to see if the middle operand is a
        # QWORD PTR or a YMMWORD PTR.
        asm = run_asm_pprinter(ir, ["--syntax=intel"])
        self.assertIn("QWORD PTR", asm)

    def test_avx512_intel(self):
        """
        This test ensures that we print avx512 instructions correctly.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        instructions = [
            (b"\x62\xF1\xE5\xC9\xD4\xCA", "vpaddq ZMM1{K1}{z},ZMM3,ZMM2"),
            (
                b"\x62\xF3\x7D\x20\x1F\x07\x00",
                "vpcmpeqd K0,YMM16,YMMWORD PTR [RDI]",
            ),
            (b"\x62\xB2\x75\x20\x26\xC9", "vptestmb K1,YMM17,YMM17"),
            (
                b"\x62\xB3\x2D\x21\x3F\xC0\x00",
                "vpcmpeqb K0{K1},YMM26,YMM16",
            ),
            (b"\x62\xF3\x45\x28\x1F\xC2\x01", "vpcmpltd K0,YMM7,YMM2"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x02", "vpcmpled K0,YMM7,YMM2"),
            (b"\x62\xF1\x45\x28\x76\xC2", "vpcmpeqd K0,YMM7,YMM2"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x04", "vpcmpneqd K0,YMM7,YMM2"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x05", "vpcmpnltd K0,YMM7,YMM2"),
            (b"\x62\xf3\x6d\x28\x1f\xc7\x06", "vpcmpnled K0,YMM2,YMM7"),
        ]

        for insn_bytes, insn_str in instructions:
            with self.subTest(instruction=insn_str):

                ir, m = create_test_module(
                    file_format=gtirb.Module.FileFormat.ELF,
                    isa=gtirb.Module.ISA.X64,
                )
                s, bi = add_text_section(m)
                add_code_block(bi, insn_bytes)
                asm = run_asm_pprinter(ir, ["--syntax=intel"])
                self.assertIn(insn_str, asm)
