package ghidra.app.util.bin.format.elf.relocation

object AllegrexElfRelocationConstants {
  const val R_MIPS_NONE = 0
  const val R_MIPS_16 = 1
  const val R_MIPS_32 = 2
  const val R_MIPS_26 = 4
  const val R_MIPS_HI16 = 5
  const val R_MIPS_LO16 = 6

  // Mapping for "new" type B relocations is rather arbitrary
  const val R_MIPS_X_HI16 = 13
  const val R_MIPS_X_J26 = 14
  const val R_MIPS_X_JAL26 = 15
}
