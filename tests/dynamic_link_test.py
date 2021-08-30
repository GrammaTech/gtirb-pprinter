import sys
import gtirb

from pprinter_helpers import run_binary_pprinter_mock_out, PPrinterTest

from gtirb_helpers import (
    create_test_module,
    add_section,
    add_text_section,
    add_code_block,
    add_function,
)


class TestDynamicLinking(PPrinterTest):
    def test_ldlinux_dep(self):
        # Check that a binary with a known dependence on ld-linux.so does
        # not try to explicity link with it, as the link should be implicit.
        ir, m = create_test_module(
            gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, ["DYN"]
        )
        add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        main = add_code_block(bi, b"\xC3")
        add_function(m, "main", main)

        m.aux_data["libraries"].data.append("ld-linux-x86-64.so.2")
        output = run_binary_pprinter_mock_out(
            ir, [], check_output=True
        ).stdout.decode(sys.stdout.encoding)

        self.assertContains("Compiler arguments:", output)
        self.assertNotContains("ld-linux", output)
