package allegrex.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfHeader
import ghidra.app.util.bin.format.elf.ElfRelocation

sealed class AllegrexRelocation {
  companion object {
    fun fromLongArray(arr: LongArray): AllegrexRelocation {
      return when (arr.size) {
        TypeA.PACKED_SIZE -> TypeA.fromLongArray(arr)
        TypeB.PACKED_SIZE -> TypeB.fromLongArray(arr)
        else -> error("Can't unpack this relocation! Unknown size: ${arr.size}")
      }
    }

    init {
      require(TypeA.PACKED_SIZE != TypeB.PACKED_SIZE)
    }
  }

  class TypeA private constructor(
    val offset: Int,
    val type: Int,
    val relativeIndex: Int,
    val relocateToIndex: Int,
    val relative: Int,
    val relocateTo: Int,
    val linkedLoValue: Int
  ) : AllegrexRelocation() {
    companion object {
      const val PACKED_SIZE = 7

      fun fromElf(header: ElfHeader, relocation: ElfRelocation, linkedLoValue: Int): TypeA {
        val info = relocation.relocationInfo.toInt()
        val type = info and 0xFF
        val relativeIndex = info shr 8 and 0xFF
        val relocateToIndex = info shr 16 and 0xFF

        val relativeSect = header.programHeaders[relativeIndex].virtualAddress.toInt()
        val relocateTo = header.programHeaders[relocateToIndex].virtualAddress.toInt()
        return TypeA(
          relocation.offset.toInt(),
          type,
          relativeIndex,
          relocateToIndex,
          relativeSect,
          relocateTo,
          linkedLoValue
        )
      }

      fun fromLongArray(arr: LongArray): TypeA {
        val packed = arr.map { it.toInt() }
        return TypeA(
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

  class TypeB(
    val offset: Int,
    val type: Int,
    val offsetBaseIndex: Int,
    val addressBaseIndex: Int,
    val offsetBase: Long,
    val addressBase: Long,
    val addend: Int,
    private val unused: Int = 0
  ) : AllegrexRelocation() {
    companion object {
      const val PACKED_SIZE = 8

      fun fromLongArray(arr: LongArray): TypeB {
        val packed = arr.map { it.toInt() }
        return TypeB(
          packed[0],
          packed[1],
          packed[2],
          packed[3],
          arr[4],
          arr[5],
          packed[6],
          packed[7]
        )
      }
    }

    fun toLongArray(): LongArray {
      return arrayOf(offset, type, offsetBaseIndex, addressBaseIndex, offsetBase, addressBase, addend, unused)
        .map { it.toLong() }
        .toLongArray()
    }
  }
}
