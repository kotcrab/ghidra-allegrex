package allegrex.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfHeader
import ghidra.app.util.bin.format.elf.ElfRelocation

class AllegrexRelocation private constructor(
  val offset: Int,
  val type: Int,
  val relativeIndex: Int,
  val relocateToIndex: Int,
  val relative: Int,
  val relocateTo: Int,
  val linkedLoValue: Int
) {
  companion object {
    fun fromElf(header: ElfHeader, relocation: ElfRelocation, linkedLoValue: Int): AllegrexRelocation {
      val info = relocation.relocationInfo.toInt()
      val type = info and 0xFF
      val relativeIndex = info shr 8 and 0xFF
      val relocateToIndex = info shr 16 and 0xFF

      val relativeSect = header.programHeaders[relativeIndex].virtualAddress.toInt()
      val relocateTo = header.programHeaders[relocateToIndex].virtualAddress.toInt()
      return AllegrexRelocation(
        relocation.offset.toInt(),
        type,
        relativeIndex,
        relocateToIndex,
        relativeSect,
        relocateTo,
        linkedLoValue
      )
    }

    fun fromLongArray(arr: LongArray): AllegrexRelocation {
      val packed = arr.map { it.toInt() }
      return AllegrexRelocation(
        packed[0],
        packed[1],
        packed[2],
        packed[3],
        packed[4],
        packed[5],
        packed[6]
      )
    }
  }

  fun toLongArray(): LongArray {
    return arrayOf(offset, type, relativeIndex, relocateToIndex, relative, relocateTo, linkedLoValue)
      .map { it.toLong() }
      .toLongArray()
  }
}
