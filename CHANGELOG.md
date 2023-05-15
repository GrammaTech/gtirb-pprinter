1.9.0
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

1.8.6
  * Add fixup for rewriting `main` symbol as global.
  * Support full paths in `--use-gcc` option.
  * Add support for ARM pc-relative `ldr` instruction with register offset.
  * Add support for ARM `trap` instructions.
  * Emit symbol declarations for symbols attached to `.plt` section.
  * Add support for TLSLDM relocationss
  * Add detection for `--export-dynamic` in binary printer.

1.8.5
  * Remove `--assembler` option; printer now always behaves correctly when
    escaping characters.
  * Support generating ELF symbol version information in assembly output.
  * Add `--version-script` argument for generating ELF version scripts.
  * Removed explicit transformations to GTIRB from PrettyPrinter. Clients
    will now need to explicitly opt in to these transforms. `gtirb-pprinter`
    behavior is unchanged.

1.8.4

  * Fix bugs in printing shift instructions in AT&T syntax.
  * Add `--use-gcc` option overriding `gcc` executable when binary printing ELF files.
  * Fix printing symbols with a displacement of zero in ARM64 indirect operands.
  * Expand `--help` message by listing options for `--isa`, `--syntax`, `--assembler`, and `--policy`.
  * Fix bug resulting in skipped `.data` sections.
  * Ubuntu 18 and gcc 7 are no longer supported.
  * Default syntax in `assembler` mode changed to AT&T (i.e., `att`).

1.8.3

  * Rename `elfSectionProperties` to sectionProperties`, and remove
  `peSectionProperties`.

1.8.2

  * Use `.ascii` directive for partial strings.

1.8.0

  * Add alternative PE assembler and linker commands.
  * Use dedicated symbolic expression attributes.
  * Add an option for assembler

1.7.0

  * Added support for MIPS and ARM32
  * Added support for MinGW for PE32+
  * Fixed bad operand size in COMISS instructions
  * Use PUBLIC entrypoint instead of EXPORT
  * Handle linking to DRV files in PE32 binaries
  * Change "isa" short option from -i to -I (-i is ir)
  * Add special KUSER_SHARED_DATA symbol
  * Handle ld-linux included as a required library
  * Fix Intel syntax for vpgatherdd

1.6.0

  * Add PE support.
  * Remove null displacement offset warning.

1.5.0

  * Add preliminary x86_32 support.

1.4.0

  * Use GTIRB symbolic expression attributes.

1.3.0

  * Add preliminary ARM64 support.
