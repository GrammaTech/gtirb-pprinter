import gtirb

from gtirb_helpers import (
    add_code_block,
    add_data_block,
    add_data_section,
    add_elf_symbol_info,
    add_section,
    add_symbol,
    add_text_section,
    create_test_module,
)
from pprinter_helpers import PPrinterTest, asm_lines, run_asm_pprinter


class BlockAlignmentTest(PPrinterTest):
    def test_block_alignment_default(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m)
        add_code_block(bi, b"\xC3")

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 16", "ret"])

    def test_block_alignment_in_aux_data(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m)
        block = add_code_block(bi, b"\xC3")

        m.aux_data["alignment"].data[block] = 32

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 32", "ret"])

    def test_block_alignment_via_bi_in_aux_data(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m)
        add_code_block(bi, b"\xC3")

        m.aux_data["alignment"].data[bi] = 32

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 32", "ret"])

    def test_block_alignment_via_section_in_aux_data(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m)
        add_code_block(bi, b"\xC3")

        m.aux_data["alignment"].data[s] = 32

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 32", "ret"])

    def test_block_alignment_via_array_section_fallback_ia32(self):
        # This tests the changes in MR 362.
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.IA32
        )
        _, bi = add_section(m, ".init_array")
        add_data_block(bi, b"\x00\x00\x00\x00")

        asm = run_asm_pprinter(ir, ["--policy=dynamic", "--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 4", ".zero 4"])

    def test_block_alignment_via_array_section_fallback_x64(self):
        # This tests the changes in MR 362.
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_section(m, ".init_array")
        add_data_block(bi, b"\x00\x00\x00\x00\x00\x00\x00\x00")

        asm = run_asm_pprinter(ir, ["--policy=dynamic", "--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 8", ".zero 8"])

    def test_block_alignment_via_address_fallback(self):
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m, address=0x1004)
        add_code_block(bi, b"\xC3")

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(asm_lines(asm), [".align 4", "ret"])

    def test_code_block_alignment_via_symbol(self):
        """
        Test that code blocks that have exported symbols are aligned by their
        address.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m)

        add_code_block(bi, b"\x90\x90")
        block = add_code_block(bi, b"\xC3")

        sym = add_symbol(m, "hello", block)
        add_elf_symbol_info(m, sym, block.size, "FUNC")

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(
            asm_lines(asm),
            [
                "nop",
                ".align 2",
                ".globl hello",
                ".type hello, @function",
                "hello:",
                "ret",
            ],
        )

    def test_data_block_alignment_via_symbol(self):
        """
        Test that data blocks that have exported symbols are *not* aligned at
        all.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_data_section(m)

        add_data_block(bi, b"\x01\x02")
        block = add_data_block(bi, b"\x03\x04")

        sym = add_symbol(m, "hello", block)
        add_elf_symbol_info(m, sym, block.size, "OBJECT")

        asm = run_asm_pprinter(ir, ["--syntax", "intel"])
        self.assertContains(
            asm_lines(asm),
            [
                ".byte 0x2",
                ".globl hello",
                ".type hello, @object",
                ".size hello, 2",
                "hello:",
                ".byte 0x3",
            ],
        )

    def test_block_alignment_pe(self):
        """
        Test that ALIGNs are printed correctly for Masm:
        ALIGN for individual block within a SEGMENT needs to match to the
        SEGMENT's ALIGN property.
        - The default ALIGN is 16. If there's any data block that requires
          bigger alignment, the printer adds `ALIGN(N)` property to the
          corresponding SEGMENT where N is the maximum alignemnt.
        - The `.data` SEGMENT is an exception because it is one of the
          predefined SEGMENTs, whose properties including `ALIGN` property
          cannot be changed.
          For any block in the segment that requires alignment bigger than 16,
          the printer adjusts its ALIGN to 16.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.PE, isa=gtirb.Module.ISA.X64
        )
        _, bi1 = add_section(m, ".data")
        data1 = add_data_block(bi1, b"\x00\x00\x00\x00")

        m.aux_data["alignment"].data[data1] = 32

        _, bi2 = add_section(m, ".rdata")
        add_data_block(bi2, b"\x01\x00\x00\x00")
        data2 = add_data_block(bi2, b"\x02\x00\x00\x00")

        m.aux_data["alignment"].data[data2] = 32

        asm = run_asm_pprinter(ir)
        self.assertContains(asm_lines(asm), ["ALIGN 16", "DB 4 DUP(0)"])
        self.assertContains(asm_lines(asm), ["_RDATA SEGMENT ALIGN(32)"])
        self.assertContains(asm_lines(asm), ["ALIGN 32", "BYTE 002H"])
