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

    def test_k_instructions(self):
        """
        This test ensures that AVX-512 K-register operands are printed using
        normal comma-separated syntax rather than the "{...}{...}{...}"
        syntax produced for some instructions.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        instructions = [
            (b"\xc5\xed\x4a\xd9", "kaddb K3,K2,K1"),
            (b"\xc5\xec\x4a\xd9", "kaddw K3,K2,K1"),
            (b"\xc4\xe1\xed\x4a\xd9", "kaddd K3,K2,K1"),
            (b"\xc4\xe1\xec\x4a\xd9", "kaddq K3,K2,K1"),
            (b"\xc5\xed\x41\xd9", "kandb K3,K2,K1"),
            (b"\xc5\xec\x41\xd9", "kandw K3,K2,K1"),
            (b"\xc4\xe1\xed\x41\xd9", "kandd K3,K2,K1"),
            (b"\xc4\xe1\xec\x41\xd9", "kandq K3,K2,K1"),
            (b"\xc5\xed\x42\xd9", "kandnb K3,K2,K1"),
            (b"\xc5\xec\x42\xd9", "kandnw K3,K2,K1"),
            (b"\xc4\xe1\xed\x42\xd9", "kandnd K3,K2,K1"),
            (b"\xc4\xe1\xec\x42\xd9", "kandnq K3,K2,K1"),
            (b"\xc5\xf9\x90\xd1", "kmovb K2,K1"),
            (b"\xc5\xf8\x90\xd1", "kmovw K2,K1"),
            (b"\xc4\xe1\xf9\x90\xd1", "kmovd K2,K1"),
            (b"\xc4\xe1\xf8\x90\xd1", "kmovq K2,K1"),
            (b"\xc5\xf9\x44\xd1", "knotb K2,K1"),
            (b"\xc5\xf8\x44\xd1", "knotw K2,K1"),
            (b"\xc4\xe1\xf9\x44\xd1", "knotd K2,K1"),
            (b"\xc4\xe1\xf8\x44\xd1", "knotq K2,K1"),
            (b"\xc5\xed\x45\xd9", "korb K3,K2,K1"),
            (b"\xc5\xec\x45\xd9", "korw K3,K2,K1"),
            (b"\xc4\xe1\xed\x45\xd9", "kord K3,K2,K1"),
            (b"\xc4\xe1\xec\x45\xd9", "korq K3,K2,K1"),
            (b"\xc5\xf9\x98\xd1", "kortestb K2,K1"),
            (b"\xc5\xf8\x98\xd1", "kortestw K2,K1"),
            (b"\xc4\xe1\xf9\x98\xd1", "kortestd K2,K1"),
            (b"\xc4\xe1\xf8\x98\xd1", "kortestq K2,K1"),
            (b"\xc4\xe3\x79\x32\xd1\x01", "kshiftlb K2,K1,1"),
            (b"\xc4\xe3\xf9\x32\xd1\x01", "kshiftlw K2,K1,1"),
            (b"\xc4\xe3\x79\x33\xd1\x01", "kshiftld K2,K1,1"),
            (b"\xc4\xe3\xf9\x33\xd1\x01", "kshiftlq K2,K1,1"),
            (b"\xc4\xe3\x79\x30\xd1\x01", "kshiftrb K2,K1,1"),
            (b"\xc4\xe3\xf9\x30\xd1\x01", "kshiftrw K2,K1,1"),
            (b"\xc4\xe3\x79\x31\xd1\x01", "kshiftrd K2,K1,1"),
            (b"\xc4\xe3\xf9\x31\xd1\x01", "kshiftrq K2,K1,1"),
            (b"\xc5\xf9\x99\xd1", "ktestb K2,K1"),
            (b"\xc5\xf8\x99\xd1", "ktestw K2,K1"),
            (b"\xc4\xe1\xf9\x99\xd1", "ktestd K2,K1"),
            (b"\xc4\xe1\xf8\x99\xd1", "ktestq K2,K1"),
            (b"\xc5\xed\x4b\xd9", "kunpckbw K3,K2,K1"),
            (b"\xc5\xec\x4b\xd9", "kunpckwd K3,K2,K1"),
            (b"\xc4\xe1\xec\x4b\xd9", "kunpckdq K3,K2,K1"),
            (b"\xc5\xed\x46\xd9", "kxnorb K3,K2,K1"),
            (b"\xc5\xec\x46\xd9", "kxnorw K3,K2,K1"),
            (b"\xc4\xe1\xed\x46\xd9", "kxnord K3,K2,K1"),
            (b"\xc4\xe1\xec\x46\xd9", "kxnorq K3,K2,K1"),
            (b"\xc5\xed\x47\xd9", "kxorb K3,K2,K1"),
            (b"\xc5\xec\x47\xd9", "kxorw K3,K2,K1"),
            (b"\xc4\xe1\xed\x47\xd9", "kxord K3,K2,K1"),
            (b"\xc4\xe1\xec\x47\xd9", "kxorq K3,K2,K1"),
            (b"\xc4\xe3\x79\x61\xc1\x08", "vpcmpestri XMM0,XMM1,8"),
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
