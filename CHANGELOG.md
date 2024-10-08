# 2.2.1 (Unreleased)

  * Fix a bug that could cause `WEAK` symbols to be not exported
  * Skip binary printing interpreters when printing multiple multiple modules
  * Require gtirb >=2.2.0
  * Fix Masm pretty-printer so that ALIGN property can be added to SEGMENT
    when it includes any data blocks that require alignment.
    For `.data` SEGMENT, which is a predefined SEGMENT, we do not change its
    ALIGN property. Instead, it adjusts the ALIGN directives of any data
    blocks that have alignment value bigger than the SEGMENT alignment.

# 2.2.0

  * Stop generating debian metapackages and packages with the version attached
    to the package name. Updates in the apt-repository now support multiple
    package versions and upgrading `gtirb-pprinter` with `apt-get upgrade`.
  * Fix dummy-so generation to use correct syntax for ARM with `--dummy-so=yes`
  * Work around ml.exe bug that could result in missing exports in x86-32 PEs.
  * Generate `-m32` when generating dummy-so libraries and object files for x86-32
  * Add fixup to strip `_copy` suffix appended by ddisasm from `__x86.get_pc_thunk.*` symbols.
  * Suppress `__x86.get_pc_thunk.*` symbols in dynamic mode.
  * Use `-nodefaultlibs` with the `complete` printing policy
  * Blacklist `_GLOBAL_OFFSET_TABLE_` symbol from dummy-so libraries.
  * Explicitly link `ld-linux*.so` if `-nodefaultlibs` is enabled.
  * Support GOT, PAGE and GOT, OFST symbolic expression attributes for split .got loads on MIPS.
  * Populate non-local symbols under `global:` in version-script.
  * Change version scripts that only use the module's symbol version
    definitions (not its needed symbols).
  * Create a different version script for dummy-so dependencies using the
    needed symbol versions.
  * Add `-Wl,-soname` argument for `elfSoname` aux-data
  * Requires gtirb >=2.1.0
  * Remove generation for `--export-dynamic`, and instead, add generation for `--dynamic-list` in binary printer
  * For ambiguous symbols, choose one symbol to keep original symbol name.
  * For symbols with base version, only print out the connector and do not
    print out the base version in .symver directives.
  * Update capstone version from 4.0.1 to 5.0.1
  * Add a fixup for `repz ret` for MASM pprinter
  * Fix a bug where FADD or FSUBR operands could be misplaced for MASM pprinter

# 2.1.0
  * `--asm` option now prints the assembly for each module of an IR separately
  * `--version-script` now prints a separate version script for each module
    of an IR
  * `--module` option deprecated
  * Binaries printed from a multi-module IR are linked against other binaries from the
    same IR whenever possible
  * Use `elfStackExec` and `elfStackSize` auxdata to generate appropriate linker flags.
  * Requires gtirb >=2.0.0
  * Set entrypoint in ELF files to `_start` symbol even if the symbol is not
    `GLOBAL`. Fixes segfaults in rewritten binaries with non-global `_start`
    symbols.
  * Fix segfault if `elfDynamicInit` or `elfDynamicFini` auxdata do not refer
    to a `CodeBlock`.
  * Use function boundaries and the `functionNames` auxdata to print `PROC` and `ENDP` directives in PE binaries.
    If the `functionNames` auxdata is not present, no `PROC` and `ENDP` directives will be printed.
  * Use function boundaries and the `functionNames` auxdata to print `.size`
    directives for `FUNC` and `GNU_IFUNC` symbols in ELF binaries associated to functions.
    If the `functionNames` auxdata is not present, no `.size` directives for functions will be printed.
  * Print `.size` directives for `TLS` symbols in ELF binaries.
  * Deprecate the `PrettyPrinterBase` methods: `getContainerFunctionName`, `getFunctionName`, `isFunctionEntry`, and `isFunctionLastBlock`; and
    the attributes: `functionEntry`, and `functionLastBlock`.

# 2.0.0
  * Remove unnecessary --isa,-I option.
  * Fix bug where a binary with COPY-relocated symbols could be missing
    DT_NEEDED entries after rewriting with `--dummy-so`.
  * Removed `--binaries` option
  * `--binary` option now links each module of the IR into a separate binary
  * Added `--object` option to print relocatable object files
  * Binary printer methods now operate on modules, rather than the entire IR
  * `--shared` option now takes an argument: either `yes`, `no`, or `auto` (`auto` uses aux_data `binaryType`)
  * Pass `-init` and `-fini` to `ld` based on `elfDynamicInit` and `elfDynamicFini` auxdata.
  * Added patterns for selecting and printing modules by names


# 1.9.0
  * Added a Python wheel to make gtirb-pprinter pip-installable.
  * Binary printer always prints against exact library versions.
  * Do not remove endbr64 instructions.
  * Fix timing issue when running llvm-config in the PE binary printer.
  * Add explicit DS register for MASM pprinter.
  * Fixup INT1 and INT3 x64 instructions.
  * Update the default `--policy` behavior for dynamically linked ELF binaries from `dynamic` to `complete`.
  * ARM: Do not rely on `ArchInfo` auxdata.
  * ARM: Fail if a CodeBlock cannot be completely disassembled.
  * Replace symbolic expression attributes with composable labels.

# 1.8.6
  * Add fixup for rewriting `main` symbol as global.
  * Support full paths in `--use-gcc` option.
  * Add support for ARM pc-relative `ldr` instruction with register offset.
  * Add support for ARM `trap` instructions.
  * Emit symbol declarations for symbols attached to `.plt` section.
  * Add support for TLSLDM relocationss
  * Add detection for `--export-dynamic` in binary printer.

# 1.8.5
  * Remove `--assembler` option; printer now always behaves correctly when
    escaping characters.
  * Support generating ELF symbol version information in assembly output.
  * Add `--version-script` argument for generating ELF version scripts.
  * Removed explicit transformations to GTIRB from PrettyPrinter. Clients
    will now need to explicitly opt in to these transforms. `gtirb-pprinter`
    behavior is unchanged.

# 1.8.4

  * Fix bugs in printing shift instructions in AT&T syntax.
  * Add `--use-gcc` option overriding `gcc` executable when binary printing ELF files.
  * Fix printing symbols with a displacement of zero in ARM64 indirect operands.
  * Expand `--help` message by listing options for `--isa`, `--syntax`, `--assembler`, and `--policy`.
  * Fix bug resulting in skipped `.data` sections.
  * Ubuntu 18 and gcc 7 are no longer supported.
  * Default syntax in `assembler` mode changed to AT&T (i.e., `att`).

# 1.8.3

  * Rename `elfSectionProperties` to `sectionProperties`, and remove
  `peSectionProperties`.

# 1.8.2

  * Use `.ascii` directive for partial strings.

# 1.8.0

  * Add alternative PE assembler and linker commands.
  * Use dedicated symbolic expression attributes.
  * Add an option for assembler

# 1.7.0

  * Added support for MIPS and ARM32
  * Added support for MinGW for PE32+
  * Fixed bad operand size in COMISS instructions
  * Use PUBLIC entrypoint instead of EXPORT
  * Handle linking to DRV files in PE32 binaries
  * Change "isa" short option from -i to -I (-i is ir)
  * Add special KUSER_SHARED_DATA symbol
  * Handle ld-linux included as a required library
  * Fix Intel syntax for vpgatherdd

# 1.6.0

  * Add PE support.
  * Remove null displacement offset warning.

# 1.5.0

  * Add preliminary x86_32 support.

# 1.4.0

  * Use GTIRB symbolic expression attributes.

# 1.3.0

  * Add preliminary ARM64 support.
