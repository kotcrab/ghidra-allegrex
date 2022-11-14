package allegrex.format.elf.relocation

import ghidra.app.plugin.core.reloc.RelocationFixupHandler
import ghidra.app.util.opinion.PspElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Processor
import ghidra.program.model.listing.Program
import ghidra.program.model.reloc.Relocation

@Suppress("unused")
class AllegrexRelocationFixupHandler : RelocationFixupHandler() {
  override fun handlesProgram(program: Program): Boolean {
    if (PspElfLoader.PSP_ELF_NAME != program.executableFormat) {
      return false
    }
    val language = program.language
    if (language.languageDescription.size != 32) {
      return false
    }
    val processor = language.processor
    return processor == Processor.findOrPossiblyCreateProcessor("Allegrex")
  }

  override fun processRelocation(
    program: Program, relocation: Relocation, oldImageBase: Address, newImageBase: Address
  ): Boolean {
    when (val allegrexReloc = AllegrexRelocation.fromLongArray(relocation.values)) {
      is AllegrexRelocation.TypeA -> {
        AllegrexRelocationApplicator.applyTo(
          program, newImageBase,
          relocation.address, relocation.bytes, allegrexReloc,
          useInstructionStasher = true, addToRelocationTable = false
        )
      }
      is AllegrexRelocation.TypeB -> {
        AllegrexRelocationApplicator.applyTo(
          program, newImageBase, allegrexReloc,
          origBytesProvider = { relocation.bytes },
          useInstructionStasher = true, addToRelocationTable = false
        )
      }
    }
    return true
  }
}
