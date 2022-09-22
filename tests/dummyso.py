import gtirb
import gtirb_test_helpers as gth

# This file provides a constructor for building the dummyso gtirb test IR.
# What we're testing here is gtirb-pprinter's ability to synthesize fake
# .so files as proxies for the actual .so files that the executable
# modeled by this gtirb depends on. The actual .so files are in the
# subdirectory dummyso_libs and are used by the test when running the
# rewritten binary. Each .so has an exported symbol that the main
# executable invokes.
#
# The main binary looks roughly like:
# _start() {
#   a();
#   b();
#   syscall(exit);
# }


def build_gtirb():
    (ir, module) = gth.create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64,
    )
    (text_section, text_bi) = gth.add_text_section(module)
    proxy_a = gth.add_proxy_block(module)
    symbol_a = gth.add_symbol(module, "a", proxy_a)
    se_a = gtirb.SymAddrConst(
        0, symbol_a, {gtirb.SymbolicExpression.Attribute.PltRef}
    )
    proxy_a2 = gth.add_proxy_block(module)
    symbol_a2 = gth.add_symbol(module, "a2", proxy_a2)
    se_a2 = gtirb.SymAddrConst(
        0, symbol_a, {gtirb.SymbolicExpression.Attribute.PltRef}
    )
    proxy_b = gth.add_proxy_block(module)
    symbol_b = gth.add_symbol(module, "b", proxy_b)
    se_b = gtirb.SymAddrConst(
        0, symbol_b, {gtirb.SymbolicExpression.Attribute.PltRef}
    )

    # For the following code:
    #    e8 00 00 00 00          callq  a@plt
    #    e8 00 00 00 00          callq  a2@plt
    #    e8 00 00 00 00          callq  b@plt
    #    48 31 c0                xor    %rax,%rax
    #    48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
    #    48 31 ff                xor    %rdi,%rdi
    #    0f 05                   syscall
    cb = gth.add_code_block(
        text_bi,
        b"\xe8\x00\x00\x00\x00"
        b"\xe8\x00\x00\x00\x00"
        b"\xe8\x00\x00\x00\x00"
        b"\x48\x31\xc0"
        b"\x48\xc7\xc0\x3c\x00\x00\x00"
        b"\x48\x31\xff"
        b"\x0f\x05",
        {1: se_a, 6: se_a2, 11: se_b},
    )
    symbol_start = gth.add_symbol(module, "_start", cb)

    module.aux_data["libraries"].data.extend(["libmya.so", "libmyb.so"])

    module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )
    module.aux_data["elfSymbolInfo"].data[symbol_a.uuid] = (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )

    module.aux_data["elfSymbolInfo"].data[symbol_a2.uuid] = (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )
    module.aux_data["elfSymbolInfo"].data[symbol_b.uuid] = (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )

    return ir
