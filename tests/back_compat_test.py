import gtirb

from gtirb_helpers import (
    create_test_module,
    add_text_section,
    add_symbol,
    add_code_block,
)
from pprinter_helpers import (
    asm_lines,
    PPrinterTest,
    run_asm_pprinter_with_outputput,
)


class TestMoffsetCompat(PPrinterTest):
    COMPAT_WARNING_MESSAGE = (
        "WARNING: using symbolic expression at offset 0 for compatibility; "
        "recreate your gtirb file with newer tools that put expressions at "
        "the correct offset. Starting in early 2022, newer versions of the "
        "pretty printer will not use expressions at offset 0."
    )

    def test_moffset_mov_ia32_correct(self):
        ir, m = create_test_module(
            gtirb.Module.FileFormat.PE, gtirb.Module.ISA.IA32
        )
        s, bi = add_text_section(m, 0x1000)
        hello_expr = gtirb.SymAddrConst(0, add_symbol(m, "hello"))

        # mov al, byte ptr [hello]
        add_code_block(bi, b"\xA0\x00\x00\x00\x00", {1: hello_expr})
        # mov ax, word ptr [hello]
        add_code_block(bi, b"\x66\xA1\x00\x00\x00\x00", {2: hello_expr})
        # mov eax, dword ptr [hello]
        add_code_block(bi, b"\xA1\x00\x00\x00\x00", {1: hello_expr})
        # mov byte ptr [hello], al
        add_code_block(bi, b"\xA2\x00\x00\x00\x00", {1: hello_expr})
        # mov word ptr [hello], ax
        add_code_block(bi, b"\x66\xA3\x00\x00\x00\x00", {2: hello_expr})
        # mov dword ptr [hello], eax
        add_code_block(bi, b"\xA3\x00\x00\x00\x00", {1: hello_expr})

        asm, output = run_asm_pprinter_with_outputput(ir)
        self.assertNotIn(self.COMPAT_WARNING_MESSAGE, output)
        self.assertContains(
            asm_lines(asm),
            (
                "mov AL,BYTE PTR [hello]",
                "mov AX,WORD PTR [hello]",
                "mov EAX,DWORD PTR [hello]",
                "mov BYTE PTR [hello],AL",
                "mov WORD PTR [hello],AX",
                "mov DWORD PTR [hello],EAX",
            ),
        )

    def test_moffset_mov_ia32_compat(self):
        ir, m = create_test_module(
            gtirb.Module.FileFormat.PE, gtirb.Module.ISA.IA32
        )
        s, bi = add_text_section(m, 0x1000)
        hello_expr = gtirb.SymAddrConst(0, add_symbol(m, "hello"))

        # mov al, byte ptr [hello]
        add_code_block(bi, b"\xA0\x00\x00\x00\x00", {0: hello_expr})
        # mov ax, word ptr [hello]
        add_code_block(bi, b"\x66\xA1\x00\x00\x00\x00", {0: hello_expr})
        # mov eax, dword ptr [hello]
        add_code_block(bi, b"\xA1\x00\x00\x00\x00", {0: hello_expr})
        # mov byte ptr [hello], al
        add_code_block(bi, b"\xA2\x00\x00\x00\x00", {0: hello_expr})
        # mov word ptr [hello], ax
        add_code_block(bi, b"\x66\xA3\x00\x00\x00\x00", {0: hello_expr})
        # mov dword ptr [hello], eax
        add_code_block(bi, b"\xA3\x00\x00\x00\x00", {0: hello_expr})

        asm, output = run_asm_pprinter_with_outputput(ir)
        self.assertIn(self.COMPAT_WARNING_MESSAGE, output)
        self.assertEqual(output.count(self.COMPAT_WARNING_MESSAGE), 1)
        self.assertContains(
            asm_lines(asm),
            (
                "mov AL,BYTE PTR [hello]",
                "mov AX,WORD PTR [hello]",
                "mov EAX,DWORD PTR [hello]",
                "mov BYTE PTR [hello],AL",
                "mov WORD PTR [hello],AX",
                "mov DWORD PTR [hello],EAX",
            ),
        )

    def test_moffset_mov_x64_correct(self):
        ir, m = create_test_module(
            gtirb.Module.FileFormat.PE, gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m, 0x1000)
        hello_expr = gtirb.SymAddrConst(0, add_symbol(m, "hello"))

        # mov rax, qword ptr [hello]
        add_code_block(
            bi, b"\x48\xA1\x00\x00\x00\x00\x00\x00\x00\x00", {2: hello_expr}
        )
        # mov qword ptr [hello], rax
        add_code_block(
            bi, b"\x48\xA3\x00\x00\x00\x00\x00\x00\x00\x00", {2: hello_expr}
        )

        asm, output = run_asm_pprinter_with_outputput(ir)
        self.assertNotIn(self.COMPAT_WARNING_MESSAGE, output)
        self.assertContains(
            asm_lines(asm),
            (
                "mov RAX,QWORD PTR [hello]",
                "mov QWORD PTR [hello],RAX",
            ),
        )

    def test_moffset_mov_x64_compat(self):
        ir, m = create_test_module(
            gtirb.Module.FileFormat.PE, gtirb.Module.ISA.X64
        )
        s, bi = add_text_section(m, 0x1000)
        hello_expr = gtirb.SymAddrConst(0, add_symbol(m, "hello"))

        # mov rax, qword ptr [hello]
        add_code_block(
            bi, b"\x48\xA1\x00\x00\x00\x00\x00\x00\x00\x00", {0: hello_expr}
        )
        # mov qword ptr [hello], rax
        add_code_block(
            bi, b"\x48\xA3\x00\x00\x00\x00\x00\x00\x00\x00", {0: hello_expr}
        )

        asm, output = run_asm_pprinter_with_outputput(ir)
        self.assertIn(self.COMPAT_WARNING_MESSAGE, output)
        self.assertEqual(output.count(self.COMPAT_WARNING_MESSAGE), 1)
        self.assertContains(
            asm_lines(asm),
            (
                "mov RAX,QWORD PTR [hello]",
                "mov QWORD PTR [hello],RAX",
            ),
        )

    def test_nonmoffset_mov(self):
        ir, m = create_test_module(
            gtirb.Module.FileFormat.PE, gtirb.Module.ISA.IA32
        )
        s, bi = add_text_section(m, 0x1000)
        hello_expr = gtirb.SymAddrConst(0, add_symbol(m, "hello"))

        add_code_block(
            bi,
            # mov edi, hello
            b"\x8B\x3D\x00\x00\x00\x00",
            # wrong symbolic offset
            {0: hello_expr},
        )
        add_code_block(
            bi,
            # mov edi, hello
            b"\x8B\x3D\x00\x00\x00\x00",
            # correct symbolic offset
            {2: hello_expr},
        )

        asm, output = run_asm_pprinter_with_outputput(ir)
        self.assertNotIn(self.COMPAT_WARNING_MESSAGE, output)
        self.assertContains(
            asm_lines(asm),
            ("mov EDI,DWORD PTR DS:[0]", "mov EDI,DWORD PTR [hello]"),
        )
