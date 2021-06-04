import os
import subprocess
import sys

import gtirb

from gtirb_helpers import (
    add_standard_aux_data_tables,
    add_code_block,
    add_text_section,
    add_function,
)
from pprinter_helpers import (
    PPrinterTest,
    temp_directory,
    pprinter_binary,
    should_print_subprocess_output,
)


class MultiModuleTests(PPrinterTest):
    def create_multi_module_ir(self) -> gtirb.IR:
        ir = gtirb.IR()

        m1 = gtirb.Module(
            name="ex",
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        m1.ir = ir
        add_standard_aux_data_tables(m1)
        _, bi1 = add_text_section(m1)
        add_function(m1, "main", add_code_block(bi1, b"\xC3"))

        m2 = gtirb.Module(
            name="fun.so",
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        m2.ir = ir
        add_standard_aux_data_tables(m2)
        _, bi2 = add_text_section(m2)
        add_function(m2, "fun", add_code_block(bi2, b"\xC3"))

        return ir

    def test_multiple_modules_disk(self):
        with temp_directory() as tmpdir:
            gtirb_path = os.path.join(tmpdir, "test.gtirb")
            self.create_multi_module_ir().save_protobuf(gtirb_path)

            asm_path_template = os.path.join(tmpdir, "two_modules{}.s")

            capture_output_args = {}
            if not should_print_subprocess_output():
                capture_output_args["stdout"] = subprocess.PIPE
                capture_output_args["stderr"] = subprocess.PIPE

            subprocess.run(
                (
                    pprinter_binary(),
                    "--ir",
                    gtirb_path,
                    "--asm",
                    asm_path_template.format(""),
                ),
                check=True,
                cwd=tmpdir,
                **capture_output_args,
            )
            with open(asm_path_template.format(""), "r") as f:
                self.assertIn(".globl main", f.read())
            with open(asm_path_template.format("1"), "r") as f:
                self.assertIn(".globl fun", f.read())

    def test_multiple_modules_stdout_m0(self):
        with temp_directory() as tmpdir:
            gtirb_path = os.path.join(tmpdir, "test.gtirb")
            self.create_multi_module_ir().save_protobuf(gtirb_path)

            output = subprocess.check_output(
                (pprinter_binary(), "--ir", gtirb_path, "-m", "0"), cwd=tmpdir,
            ).decode(sys.stdout.encoding)
            self.assertIn(".globl main", output)
            self.assertNotIn(".globl fun", output)

    def test_multiple_modules_stdout_m1(self):
        with temp_directory() as tmpdir:
            gtirb_path = os.path.join(tmpdir, "test.gtirb")
            self.create_multi_module_ir().save_protobuf(gtirb_path)

            output = subprocess.check_output(
                (pprinter_binary(), "--ir", gtirb_path, "-m", "1"), cwd=tmpdir,
            ).decode(sys.stdout.encoding)
            self.assertNotIn(".globl main", output)
            self.assertIn(".globl fun", output)
