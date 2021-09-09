package allegrex.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfLoadHelper
import ghidra.app.util.bin.format.elf.ElfProgramHeader
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants
import ghidra.app.util.bin.format.elf.PspElfConstants
import ghidra.app.util.bin.format.elf.relocation.AllegrexElfRelocationConstants
import ghidra.util.Msg

class AuxRelocationProcessor {
  companion object {
    private val relocTypes = listOf(PspElfConstants.SHT_PSP_REL, PspElfConstants.SHT_PSP_REL_TYPE_B)
  }

  fun process(elfLoadHelper: ElfLoadHelper, useRebootBinMapping: Boolean) {
    val elfHeader = elfLoadHelper.elfHeader

    // kernel module most likely won't have any sections but this check is more permissive
    if (elfHeader.sections.any { it.type in relocTypes }) {
      return
    }

    elfHeader.programHeaders.forEach {
      when (it.type) {
        PspElfConstants.SHT_PSP_REL -> {
          elfLoadHelper.log("Type A relocations are not currently supported for ELFs without sections. Please report this.")
        }
        PspElfConstants.SHT_PSP_REL_TYPE_B -> {
          runCatching {
            processRelocationsTypeB(elfLoadHelper, it, useRebootBinMapping)
          }.onFailure { cause ->
            Msg.error("Can't process type B relocations!", cause)
            elfLoadHelper.log("Can't process type B relocations: ${cause.message}. Please report this.")
          }
        }
      }
    }
  }

  private fun processRelocationsTypeB(elfLoadHelper: ElfLoadHelper, header: ElfProgramHeader, useRebootBinMapping: Boolean) {
    val program = elfLoadHelper.program
    val relocations = parseRelocationsTypeB(elfLoadHelper.elfHeader.programHeaders, header, useRebootBinMapping)
    relocations.forEach { relocation ->
      AllegrexRelocationApplicator.applyTo(
        program, program.imageBase, relocation,
        origBytesProvider = { address ->
          val origBytes = ByteArray(4)
          program.memory.getBytes(address, origBytes)
          origBytes
        },
        useInstructionStasher = false, addToRelocationTable = true
      )
    }
  }

  private fun parseRelocationsTypeB(
    programHeaders: Array<ElfProgramHeader>,
    relocHeader: ElfProgramHeader,
    useRebootBinMapping: Boolean
  ): List<AllegrexRelocation.TypeB> {
    val relocations = mutableListOf<AllegrexRelocation.TypeB>()

    // based on PRXTool
    val reader = relocHeader.reader
    reader.pointerIndex = relocHeader.offset + 2

    val part1Size = reader.readNextUnsignedByte()
    val part2Size = reader.readNextUnsignedByte()
    val block1 = reader.pointerIndex
    val block1Size = reader.readNextUnsignedByte()
    val block2 = block1 + block1Size
    reader.pointerIndex = block2
    val block2Size = reader.readNextUnsignedByte()

    val start = block2 + block2Size
    val end = relocHeader.offset + relocHeader.fileSize

    val loadableCount = programHeaders.count { it.type == ElfProgramHeaderConstants.PT_LOAD }
    val nBits = if (loadableCount < 3) 1 else 2

    var offset = 0
    var offsetBase = 0
    var lastPart2 = block2Size
    reader.pointerIndex = start
    while (reader.pointerIndex < end) {
      val cmd = reader.readNextUnsignedShort()

      var part1Offset = (cmd shl (16 - part1Size)) and 0xFFFF
      part1Offset = (part1Offset shr (16 - part1Size)) and 0xFFFF
      if (part1Offset > block1Size) {
        error("Invalid part1 offset: $part1Offset")
      }
      val part1 = reader.readUnsignedByte(block1 + part1Offset)

      if (part1 and 0x1 == 0) {
        offsetBase = (cmd shl (16 - part1Size - nBits)) and 0xFFFF
        offsetBase = (offsetBase shr (16 - nBits)) and 0xFFFF
        if (offsetBase >= loadableCount) {
          error("Invalid offset base: $offsetBase")
        }

        when {
          part1 and 0x06 == 0 -> offset = cmd shr (part1Size + nBits)
          part1 and 0x06 == 4 -> offset = reader.readNextInt()
          else -> println("Invalid offset (part1=$part1)")
        }
      } else {
        var part2Offset = (cmd shl 16 - (part1Size + nBits + part2Size)) and 0xFFFF
        part2Offset = (part2Offset shr (16 - part2Size)) and 0xFFFF
        if (part2Offset > block2Size) {
          error("Invalid part2 offset: $part2Offset")
        }
        val part2 = reader.readUnsignedByte(block2 + part2Offset)

        var addressBase = (cmd shl (16 - part1Size - nBits)) and 0xFFFF
        addressBase = (addressBase shr (16 - nBits)) and 0xFFFF
        if (addressBase >= loadableCount) {
          error("Invalid address base: $addressBase")
        }

        when (part1 and 0x06) {
          0 -> {
            var delta = cmd
            if (delta and 0x8000 != 0) {
              delta = delta or 0xFFFF.inv()
              delta = delta shr part1Size + part2Size + nBits
              delta = delta or 0xFFFF.inv()
            } else {
              delta = delta shr part1Size + part2Size + nBits
            }
            offset += delta
          }
          2 -> {
            var delta = cmd
            if (delta and 0x8000 != 0) {
              delta = delta or 0xFFFF.inv()
            }
            delta = (delta shr (part1Size + part2Size + nBits)) shl 16
            delta = delta or reader.readNextUnsignedShort()
            offset += delta
          }
          4 -> {
            offset = reader.readNextInt()
          }
          else -> {
            error("Invalid part1 offset config: $part1")
          }
        }

        if (offset >= programHeaders[offsetBase].fileSize) {
          error("Invalid relocation offset (out of bounds) (offset=$offset)")
        }

        var addend: Short = 0
        when (part1 and 0x38) {
          0 -> {
            addend = 0
          }
          0x08 -> {
            if (lastPart2 xor 0x04 != 0) {
              addend = 0
            }
          }
          0x10 -> {
            addend = reader.readNextShort()
          }
          else -> {
            error("Invalid addend size (part1=$part1)")
          }
        }
        lastPart2 = part2

        val type = if (useRebootBinMapping) {
          when (part2) {
            0 -> AllegrexElfRelocationConstants.R_MIPS_NONE
            1 -> AllegrexElfRelocationConstants.R_MIPS_26
            2 -> AllegrexElfRelocationConstants.R_MIPS_X_J26
            3 -> AllegrexElfRelocationConstants.R_MIPS_X_JAL26
            4, 7 -> AllegrexElfRelocationConstants.R_MIPS_16
            5 -> AllegrexElfRelocationConstants.R_MIPS_32
            6 -> AllegrexElfRelocationConstants.R_MIPS_X_HI16
            else -> error("Unsupported type B relocation: $part2")
          }
        } else {
          when (part2) {
            0 -> AllegrexElfRelocationConstants.R_MIPS_NONE
            1, 5 -> AllegrexElfRelocationConstants.R_MIPS_LO16
            2 -> AllegrexElfRelocationConstants.R_MIPS_32
            3 -> AllegrexElfRelocationConstants.R_MIPS_26
            4 -> AllegrexElfRelocationConstants.R_MIPS_X_HI16
            6 -> AllegrexElfRelocationConstants.R_MIPS_X_J26
            7 -> AllegrexElfRelocationConstants.R_MIPS_X_JAL26
            else -> error("Unsupported type B relocation: $part2")
          }
        }

        relocations.add(
          AllegrexRelocation.TypeB(
            offset,
            type,
            offsetBase,
            addressBase,
            programHeaders[offsetBase].virtualAddress,
            programHeaders[addressBase].virtualAddress,
            when (type) {
              AllegrexElfRelocationConstants.R_MIPS_X_HI16 -> addend.toInt()
              else -> 0
            }
          )
        )
      }
    }

    return relocations
  }
}
