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
        # Check that a binary with a known dependence on ld-linux.so
        # explicitly links it only when passing -nodefaultlibs
        ir, m = create_test_module(
            gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, ["DYN"]
        )
        add_section(m, ".dynamic")
        _, bi = add_text_section(m)
        main = add_code_block(bi, b"\xC3")
        add_function(m, "main", main)
        m.aux_data["libraries"].data.append("ld-linux-x86-64.so.2")

        cases = [
            ("complete", True),
            ("dynamic", False),
        ]

        for policy, use_ld in cases:
            with self.subTest(policy=policy):
                output = run_binary_pprinter_mock_out(
                    ir, ["--policy", policy], check_output=True
                ).stdout.decode(sys.stdout.encoding)

                self.assertIn("Compiler arguments:", output)

                if use_ld:
                    self.assertIn("-nodefaultlibs", output)
                    self.assertIn("ld-linux", output)
                else:
                    self.assertNotIn("-nodefaultlibs", output)
                    self.assertNotIn("ld-linux", output)
