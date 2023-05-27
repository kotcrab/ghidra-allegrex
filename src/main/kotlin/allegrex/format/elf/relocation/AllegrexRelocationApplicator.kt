package allegrex.format.elf.relocation

import allegrex.MipsInstructionStasher
import ghidra.app.util.bin.format.elf.relocation.AllegrexElfRelocationConstants
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.reloc.Relocation
import ghidra.util.LittleEndianDataConverter

object AllegrexRelocationApplicator {
  fun applyTo(
    program: Program,
    imageBase: Address,
    address: Address,
    origBytes: ByteArray,
    relocation: AllegrexRelocation.TypeA,
    useInstructionStasher: Boolean,
    addToRelocationTable: Boolean,
  ) {
    val relocateToSect = imageBase.add(relocation.relocateTo.toLong()).offset.toInt()
    val initialValue = LittleEndianDataConverter.INSTANCE.getInt(origBytes)
    val newInstr: Int
    when (relocation.type) {
      AllegrexElfRelocationConstants.R_MIPS_NONE -> {
        return
      }
      AllegrexElfRelocationConstants.R_MIPS_16 -> {
        newInstr = calculateTypeA(initialValue, 0xFFFF, relocateToSect)
      }
      AllegrexElfRelocationConstants.R_MIPS_32 -> {
        newInstr = initialValue + relocateToSect
      }
      AllegrexElfRelocationConstants.R_MIPS_26 -> {
        newInstr = calculateTypeA(initialValue, 0x3FFFFFF, relocateToSect shr 2)
      }
      AllegrexElfRelocationConstants.R_MIPS_HI16 -> {
        var newAddr = initialValue shl 16
        newAddr += relocation.linkedLoValue
        newAddr += relocateToSect
        val newLo = (newAddr and 0xFFFF).toShort()
        val newHi = (newAddr - newLo) shr 16
        newInstr = (initialValue and 0xFFFF0000.toInt()) or newHi
      }
      AllegrexElfRelocationConstants.R_MIPS_LO16 -> {
        newInstr = calculateTypeA(initialValue, 0xFFFF, relocateToSect)
      }
      else -> {
        error("Missing type A relocation handler: ${relocation.type}")
      }
    }

    commitRelocation(program, address, newInstr, relocation, origBytes, useInstructionStasher, addToRelocationTable)
  }

  private fun calculateTypeA(data: Int, mask: Int, relocateTo: Int): Int {
    return (data and mask.inv()) or (((data and mask) + relocateTo) and mask)
  }

  fun applyTo(
    program: Program,
    imageBase: Address,
    relocation: AllegrexRelocation.TypeB,
    origBytesProvider: (Address) -> ByteArray,
    useInstructionStasher: Boolean,
    addToRelocationTable: Boolean,
  ) {
    val vAddr = imageBase.add(relocation.addressBase).offset.toInt()
    val address = imageBase.add(relocation.offsetBase + relocation.offset)

    val origBytes = origBytesProvider(address)
    val currentInstr = LittleEndianDataConverter.INSTANCE.getInt(origBytes)

    val newInstr = when (relocation.type) {
      AllegrexElfRelocationConstants.R_MIPS_16, AllegrexElfRelocationConstants.R_MIPS_LO16 -> {
        val newData = (vAddr + currentInstr.toShort().toInt()) and 0xffff
        newData or (currentInstr and 0xffff.inv())
      }
      AllegrexElfRelocationConstants.R_MIPS_32 -> {
        currentInstr + vAddr
      }
      AllegrexElfRelocationConstants.R_MIPS_26 -> {
        val newData = ((currentInstr and 0x3ffffff) * 4 + vAddr) * 0x10 ushr 6
        newData or (currentInstr and 0xfc000000.toInt())
      }
      AllegrexElfRelocationConstants.R_MIPS_X_HI16 -> {
        val newData = ((((currentInstr * 0x10000 + relocation.addend + vAddr) ushr 0xf) + 1) * 0x8000) ushr 0x10
        newData or (currentInstr and 0xffff.inv())
      }
      AllegrexElfRelocationConstants.R_MIPS_X_J26 -> {
        val newData = ((currentInstr and 0x3ffffff) * 4 + vAddr) * 0x10 ushr 6
        newData or 0x8000000
      }
      AllegrexElfRelocationConstants.R_MIPS_X_JAL26 -> {
        val newData = ((currentInstr and 0x3ffffff) * 4 + vAddr) * 0x10 ushr 6
        newData or 0xc000000
      }
      else -> {
        error("Missing type B relocation handler: ${relocation.type}")
      }
    }

    commitRelocation(program, address, newInstr, relocation, origBytes, useInstructionStasher, addToRelocationTable)
  }

  private fun commitRelocation(
    program: Program,
    address: Address,
    newInstr: Int,
    relocation: AllegrexRelocation,
    origBytes: ByteArray,
    useInstructionStasher: Boolean,
    addToRelocationTable: Boolean,
  ) {
    val instructionStasher = when {
      useInstructionStasher -> MipsInstructionStasher(program, address)
      else -> null
    }
    program.memory.setInt(address, newInstr)
    instructionStasher?.restore()

    if (addToRelocationTable) {
      program.relocationTable.add(address, Relocation.Status.APPLIED, relocation.type, relocation.toLongArray(), origBytes, null)
    }
  }
}
