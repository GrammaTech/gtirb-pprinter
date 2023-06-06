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
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    (text_section, text_bi) = gth.add_text_section(module)
    proxy_a = gth.add_proxy_block(module)
    symbol_a = gth.add_symbol(module, "a", proxy_a)
    se_a = gtirb.SymAddrConst(
        0, symbol_a, {gtirb.SymbolicExpression.Attribute.PLT}
    )
    proxy_a2 = gth.add_proxy_block(module)
    symbol_a2 = gth.add_symbol(module, "a2", proxy_a2)
    se_a2 = gtirb.SymAddrConst(
        0, symbol_a, {gtirb.SymbolicExpression.Attribute.PLT}
    )
    proxy_b = gth.add_proxy_block(module)
    symbol_b = gth.add_symbol(module, "b", proxy_b)
    se_b = gtirb.SymAddrConst(
        0, symbol_b, {gtirb.SymbolicExpression.Attribute.PLT}
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


def build_copy_relocated_gtirb() -> gtirb.IR:
    """
    Build a GTIRB where its only external symbols are members of a single
    COPY-relocated group.
    """
    (ir, module) = gth.create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    (text_section, text_bi) = gth.add_text_section(module)

    _, data = gth.add_data_section(module)
    data_block = gth.add_data_block(data, b"\x01\x00\x00\x00")

    # Add a COPY-relocated symbol.
    symbol_proxy = gth.add_symbol(
        module, "__lib_value", gth.add_proxy_block(module)
    )
    symbol_copy = gth.add_symbol(module, "__lib_value_copy", data_block)

    symbol_proxy_weak = gth.add_symbol(
        module, "__lib_value_weak", gth.add_proxy_block(module)
    )
    symbol_copy_weak = gth.add_symbol(
        module, "__lib_value_weak_copy", data_block
    )

    se_symbol_copy = gtirb.SymAddrConst(0, symbol_copy, {})

    # For the following code:
    #    48 89 1d 00 00 00 00    movq   %rax, __lib_value(%rip)
    #    48 31 c0                xor    %rax,%rax
    #    48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
    #    48 31 ff                xor    %rdi,%rdi
    #    0f 05                   syscall
    cb = gth.add_code_block(
        text_bi,
        b"\x48\x89\x1d\x00\x00\x00\x00"
        b"\x48\x31\xc0"
        b"\x48\xc7\xc0\x3c\x00\x00\x00"
        b"\x48\x31\xff"
        b"\x0f\x05",
        {3: se_symbol_copy},
    )
    symbol_start = gth.add_symbol(module, "_start", cb)

    module.aux_data["libraries"].data.append("libvalue.so")

    module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )

    module.aux_data["elfSymbolInfo"].data[symbol_copy.uuid] = (
        4,
        "OBJECT",
        "GLOBAL",
        "DEFAULT",
        1,
    )

    module.aux_data["elfSymbolInfo"].data[symbol_copy_weak.uuid] = (
        4,
        "OBJECT",
        "WEAK",
        "DEFAULT",
        1,
    )

    module.aux_data["symbolForwarding"].data[symbol_copy.uuid] = symbol_proxy
    module.aux_data["symbolForwarding"].data[
        symbol_copy_weak.uuid
    ] = symbol_proxy_weak

    return ir


def build_tls_gtirb() -> gtirb.IR:
    """
    Build a GTIRB that links a TLS symbol
    """
    (ir, module) = gth.create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    (text_section, text_bi) = gth.add_text_section(module)

    _, got = gth.add_section(module, ".got")
    got_data_block = gth.add_data_block(got, b"\x00\x00\x00\x00")

    symbol_proxy = gth.add_symbol(
        module, "__lib_value", gth.add_proxy_block(module)
    )

    symbol_got = gth.add_symbol(module, ".L_1abc0", got_data_block)

    se_symbol_got = gtirb.SymAddrConst(
        0,
        symbol_got,
        {
            gtirb.SymbolicExpression.Attribute.GOT,
            gtirb.SymbolicExpression.Attribute.TPOFF,
        },
    )

    # For the following code:
    #    48 8b 05 00 00 00 00    mov    __lib_value@GOTTPOFF(%rip), %rax
    #    48 31 c0                xor    %rax,%rax
    #    48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
    #    48 31 ff                xor    %rdi,%rdi
    #    0f 05                   syscall
    cb = gth.add_code_block(
        text_bi,
        b"\x48\x8b\x05\x00\x00\x00\x00"
        b"\x48\x31\xc0"
        b"\x48\xc7\xc0\x3c\x00\x00\x00"
        b"\x48\x31\xff"
        b"\x0f\x05",
        {3: se_symbol_got},
    )
    symbol_start = gth.add_symbol(module, "_start", cb)

    module.aux_data["libraries"].data.append("libvalue.so")

    module.aux_data["elfSymbolInfo"].data[symbol_start.uuid] = (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )

    module.aux_data["elfSymbolInfo"].data[symbol_proxy.uuid] = (
        0,
        "TLS",
        "GLOBAL",
        "DEFAULT",
        0,
    )

    module.aux_data["elfSymbolInfo"].data[symbol_got.uuid] = (
        0,
        "NONE",
        "LOCAL",
        "DEFAULT",
        0,
    )

    module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
        type_name=(
            "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,"
            "mapping<string,mapping<uint16_t,string>>,"
            "mapping<UUID,tuple<uint16_t,bool>>>"
        ),
        data=(
            # ElfSymVerDefs
            {},
            # ElfSymVerNeeded
            {"libvalue.so": {1: "LIBVALUE_1.0"}},
            # ElfSymbolVersionsEntries
            {symbol_proxy.uuid: (1, False)},
        ),
    )

    module.aux_data["symbolForwarding"].data[symbol_got.uuid] = symbol_proxy

    return ir


def build_plt_sec_gtirb() -> gtirb.IR:
    """
    Build a GTIRB that has .plt.sec and a reference to it
    """
    (ir, module) = gth.create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    plt_section, plt = gth.add_section(module, ".plt.sec")
    plt_code_block = gth.add_code_block(plt, b"\x00\x00\x00\x00")

    symbol_a = gth.add_symbol(module, "a", plt_code_block)

    se_a = gtirb.SymAddrConst(
        0, symbol_a, {gtirb.SymbolicExpression.Attribute.PLT}
    )

    # This is an artificial self symbol-forwarding to demonstrate
    # the case where a symbol is attached to a PLT block instead of a proxy
    # block. This test is to make sure that the symbol definition is emitted
    # in dummyso.
    module.aux_data["symbolForwarding"].data[symbol_a] = symbol_a

    _, text_bi = gth.add_text_section(module)

    # For the following code:
    #    e8 00 00 00 00          callq  a@plt
    #    48 31 c0                xor    %rax,%rax
    #    48 c7 c0 3c 00 00 00    mov    $0x3c,%rax
    #    48 31 ff                xor    %rdi,%rdi
    #    0f 05                   syscall
    cb = gth.add_code_block(
        text_bi,
        b"\xe8\x00\x00\x00\x00"
        b"\x48\x31\xc0"
        b"\x48\xc7\xc0\x3c\x00\x00\x00"
        b"\x48\x31\xff"
        b"\x0f\x05",
        {1: se_a},
    )
    symbol_start = gth.add_symbol(module, "_start", cb)

    module.aux_data["libraries"].data.extend(["libmya.so"])

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

    return ir
