package com.kotcrab.ghidra.allegrex.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfHeader
import ghidra.app.util.bin.format.elf.ElfRelocation

class AllegrexRelocation private constructor(
    val offset: Int,
    val type: Int,
    val relativeIndex: Int,
    val relocateToIndex: Int,
    val relative: Int,
    val relocateTo: Int
) {
    companion object {
        fun fromElf(header: ElfHeader, reloc: ElfRelocation): AllegrexRelocation {
            val info = reloc.relocationInfo.toInt()
            val type = info and 0xFF
            val relativeIndex = info shr 8 and 0xFF
            val relocateToIndex = info shr 16 and 0xFF
            val relative = header.programHeaders[relativeIndex].virtualAddress.toInt()
            val relocateTo = header.programHeaders[relocateToIndex].virtualAddress.toInt()
            return AllegrexRelocation(reloc.offset.toInt(), type, relativeIndex, relocateToIndex, relative, relocateTo)
        }

        fun fromLongArray(arr: LongArray): AllegrexRelocation {
            val packed = arr.map { it.toInt() }
            return AllegrexRelocation(packed[0], packed[1], packed[2], packed[3], packed[4], packed[5])
        }
    }

    fun toLongArray(): LongArray {
        return arrayOf(offset, type, relativeIndex, relocateToIndex, relative, relocateTo)
            .map { it.toLong() }
            .toLongArray()
    }
}
