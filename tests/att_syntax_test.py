import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class ATTInstructionsTest(PPrinterTest):
    def _assert_att_insn(self, insn_bytes, insn_str):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        s, bi = add_text_section(m)
        add_code_block(bi, insn_bytes)
        asm = run_asm_pprinter(ir, ["--syntax=att"])
        self.assertIn(insn_str, asm)

    def test_avx512_att(self):
        """
        This test ensures that we print avx512 instructions correctly.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)

        instructions = [
            (b"\x62\xF1\xE5\xC9\xD4\xCA", "vpaddq %zmm2,%zmm3,%zmm1{%k1}{z}"),
            (b"\x62\xF3\x7D\x20\x1F\x07\x00", "vpcmpeqd (%rdi),%ymm16,%k0"),
            (b"\x62\xB2\x75\x20\x26\xC9", "vptestmb %ymm17,%ymm17,%k1"),
            (
                b"\x62\xB3\x2D\x21\x3F\xC0\x00",
                "vpcmpeqb %ymm16,%ymm26,%k0{%k1}",
            ),
            (b"\x62\xF3\x45\x28\x1F\xC2\x01", "vpcmpltd %ymm2,%ymm7,%k0"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x02", "vpcmpled %ymm2,%ymm7,%k0"),
            (b"\x62\xF1\x45\x28\x76\xC2", "vpcmpeqd %ymm2,%ymm7,%k0"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x04", "vpcmpneqd %ymm2,%ymm7,%k0"),
            (b"\x62\xF3\x45\x28\x1F\xC2\x05", "vpcmpnltd %ymm2,%ymm7,%k0"),
            (b"\x62\xf3\x6d\x28\x1f\xc7\x06", "vpcmpnled %ymm7,%ymm2,%k0"),
        ]

        for insn_bytes, insn_str in instructions:
            self._assert_att_insn(insn_bytes, insn_str)

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
            self._assert_att_insn(insn_bytes, insn_str)

    def test_xabort_att(self):
        """
        Ensure xabort's 1-byte immediate operand is printed as unsigned hex
        rather than a signed integer for newer assembler compatibility.
        """
        self._assert_att_insn(b"\xC6\xF8\xFF", "xabort $0xFF")
