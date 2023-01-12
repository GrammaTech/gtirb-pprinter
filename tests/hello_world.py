"""
Build a minimal X86-64 hello world GTIRB file.
"""

import gtirb

from gtirb_helpers import (
    create_test_module,
    add_elf_symbol_info,
    add_text_section,
    add_data_section,
    add_symbol,
    add_code_block,
    add_data_block,
)


def build_gtirb():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    # Add .data section.
    s, bi = add_data_section(m, 0x4000A8)
    block = add_data_block(bi, b"hello world\n")
    hello = add_symbol(m, "hello", block)
    m.aux_data["encodings"].data[block.uuid] = "string"

    # Add .text section.
    s, bi = add_text_section(m, 0x400080)

    # mov eax, 1
    block = add_code_block(bi, b"\xB8\x01\x00\x00\x00")
    start = add_symbol(m, "_start", block)
    add_elf_symbol_info(m, start, block.size, "FUNC")

    # mov ebx, 1
    add_code_block(bi, b"\xBB\x01\x00\x00\x00")
    # mov rsi, hello
    operand = gtirb.SymAddrConst(0, hello)
    add_code_block(
        bi, b"\x48\xBE\xA8\x00\x40\x00\x00\x00\x00\x00", {2: operand}
    )
    # mov rsi, 13
    add_code_block(bi, b"\xBA\x0D\x00\x00\x00")
    # syscall
    add_code_block(bi, b"\x0F\x05")
    # mov eax, 60
    add_code_block(bi, b"\xB8\x3C\x00\x00\x00")
    # mov edi, 0
    add_code_block(bi, b"\xBF\x00\x00\x00\x00")
    # syscall
    add_code_block(bi, b"\x0F\x05")

    return ir


if __name__ == "__main__":
    # Save GTIRB file
    ir = build_gtirb()
    ir.save_protobuf("hello.gtirb")
