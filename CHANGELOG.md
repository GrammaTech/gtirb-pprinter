1.8.3 (Unreleased)
  * TBD

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
