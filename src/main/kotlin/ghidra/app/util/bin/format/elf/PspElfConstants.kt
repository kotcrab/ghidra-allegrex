package ghidra.app.util.bin.format.elf

@Suppress("MayBeConstant")
object PspElfConstants {
  /**
   * This is a horrible hack. This arbitrary value is used as fake e_machine in ELF header.
   * Why? Basically when performing relocations the extension class loader mechanism can select built-in
   * MIPS_ElfRelocationHandler instead of AllegrexElfRelocationHandler. Both classes say then can relocate MIPS ELF.
   * This selection is done for every section and it involves converting set to a list, thus effectively choosing random
   * handler for each section. This will make MIPS_ElfRelocationHandler return false when checking for available
   * relocation handlers
   */
  val EM_MIPS_PSP_HACK = 0x1337.toShort()

  val ET_PSP_PRX = 0xFFA0.toShort()

  val SHT_PSP_REL = 0x700000A0
}
