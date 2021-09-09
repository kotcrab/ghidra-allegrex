package allegrex.format.elf.relocation

import allegrex.MipsInstructionStasher
import ghidra.app.plugin.core.reloc.RelocationFixupHandler
import ghidra.app.util.bin.format.elf.relocation.AllegrexElfRelocationConstants
import ghidra.app.util.opinion.PspElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Processor
import ghidra.program.model.listing.Program
import ghidra.program.model.reloc.Relocation
import ghidra.util.LittleEndianDataConverter

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
    return when (val allegrexReloc = AllegrexRelocation.fromLongArray(relocation.values)) {
      is AllegrexRelocation.TypeA -> processRelocationTypeA(program, relocation, allegrexReloc, newImageBase)
      is AllegrexRelocation.TypeB -> {
        AllegrexRelocationApplicator.applyTo(
          program, newImageBase, allegrexReloc,
          origBytesProvider = { relocation.bytes },
          useInstructionStasher = true, addToRelocationTable = false
        )
        true
      }
    }
  }

  private fun processRelocationTypeA(
    program: Program, relocation: Relocation, allegrexReloc: AllegrexRelocation.TypeA, newImageBase: Address
  ): Boolean {
    val memory = program.memory
    val addr = relocation.address
    val relocateToSect = newImageBase.add(allegrexReloc.relocateTo.toLong()).offset.toInt()
    val initialValue = LittleEndianDataConverter.INSTANCE.getInt(relocation.bytes)
    val newValue: Int
    when (relocation.type) {
      AllegrexElfRelocationConstants.R_MIPS_NONE -> {
        return true
      }
      AllegrexElfRelocationConstants.R_MIPS_16 -> {
        newValue = relocate(initialValue, 0xFFFF, relocateToSect)
      }
      AllegrexElfRelocationConstants.R_MIPS_32 -> {
        newValue = initialValue + relocateToSect
      }
      AllegrexElfRelocationConstants.R_MIPS_26 -> {
        newValue = relocate(initialValue, 0x3FFFFFF, relocateToSect shr 2)
      }
      AllegrexElfRelocationConstants.R_MIPS_HI16 -> {
        var newAddr = initialValue shl 16
        newAddr += allegrexReloc.linkedLoValue
        newAddr += relocateToSect
        val newLo = (newAddr and 0xFFFF).toShort()
        val newHi = (newAddr - newLo) shr 16
        newValue = (initialValue and 0xFFFF0000.toInt()) or newHi
      }
      AllegrexElfRelocationConstants.R_MIPS_LO16 -> {
        newValue = relocate(initialValue, 0xFFFF, relocateToSect)
      }
      else -> return false
    }
    if (newValue == 0) {
      return false
    }
    val instructionStasher = MipsInstructionStasher(program, addr)
    memory.setInt(addr, newValue)
    instructionStasher.restore()
    return true
  }

  private fun relocate(data: Int, mask: Int, relocateTo: Int): Int {
    return (data and mask.inv()) or (((data and mask) + relocateTo) and mask)
  }
}
