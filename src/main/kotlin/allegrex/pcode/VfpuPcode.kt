package allegrex.pcode

import ghidra.program.model.pcode.Varnode

object VfpuPcode {
  private const val VFPU_REGS_START = 0x5000
  private const val UNREACHABLE_MESSAGE = "This should be unreachable"

  fun mapBaseRegToModePair(varnode: Varnode): Pair<Int, Int> {
    val regId = regVarnodeToRegId(varnode)
    val bankId = regId and 0xF0
    val stride = if (regId and 0b100 == 0b100) 1 else 4
    val baseRegId = when (regId and 0xF) {
      0x0 -> 0x0 // C000
      0x1 -> 0x1 // C010
      0x2 -> 0x2 // C020
      0x3 -> 0x3 // C030
      0x4 -> 0x0 // R000
      0x5 -> 0x4 // R001
      0x6 -> 0x8 // R002
      0x7 -> 0xC // R003
      0x8 -> 0x8 // C002
      0x9 -> 0x9 // C012
      0xA -> 0xA // C022
      0xB -> 0xB // C032
      0xC -> 0x2 // R020
      0xD -> 0x6 // R021
      0xE -> 0xA // R022
      0xF -> 0xE // R023
      else -> error(UNREACHABLE_MESSAGE)
    }
    return Pair(bankId or baseRegId, stride)
  }

  fun mapBaseRegToModeTriple(varnode: Varnode): Pair<Int, Int> {
    val regId = regVarnodeToRegId(varnode)
    val bankId = regId and 0xF0
    val stride = if (regId and 0b100 == 0b100) 1 else 4
    val baseRegId = when (regId and 0xF) {
      0x0 -> 0x0 // C000
      0x1 -> 0x1 // C010
      0x2 -> 0x2 // C020
      0x3 -> 0x3 // C030
      0x4 -> 0x0 // R000
      0x5 -> 0x4 // R001
      0x6 -> 0x8 // R002
      0x7 -> 0xC // R003
      0x8 -> 0x4 // C001
      0x9 -> 0x5 // C011
      0xA -> 0x6 // C021
      0xB -> 0x7 // C031
      0xC -> 0x1 // R010
      0xD -> 0x5 // R011
      0xE -> 0x9 // R012
      0xF -> 0xD // R013
      else -> error(UNREACHABLE_MESSAGE)
    }
    return Pair(bankId or baseRegId, stride)
  }


  fun mapBaseRegToModeQuad(varnode: Varnode): Pair<Int, Int> {
    val regId = regVarnodeToRegId(varnode)
    val bankId = regId and 0xF0
    val stride = if (regId and 0b100 == 0b100) 1 else 4
    val baseRegId = when (regId and 0xF) {
      0x0 -> 0x0 // C000
      0x1 -> 0x1 // C010
      0x2 -> 0x2 // C020
      0x3 -> 0x3 // C030
      0x4 -> 0x0 // R000
      0x5 -> 0x4 // R001
      0x6 -> 0x8 // R002
      0x7 -> 0xC // R003
      0x8 -> 0x0 // C002
      0x9 -> 0x1 // C012
      0xA -> 0x2 // C022
      0xB -> 0x3 // C032
      0xC -> 0x0 // R020
      0xD -> 0x4 // R021
      0xE -> 0x8 // R022
      0xF -> 0xC // R023
      else -> error(UNREACHABLE_MESSAGE)
    }
    return Pair(bankId or baseRegId, stride)
  }

  fun mapBaseRegToModeMatrix2(varnode: Varnode): Pair<Int, Boolean> {
    val regId = regVarnodeToRegId(varnode)
    val bankId = regId and 0xF0
    val transpose = regId and 0b100 == 0b100
    // not sure how illegal options are handled, just assign to the closest possible matrix for now (same for 3x3 matrix)
    val baseRegId = when (regId and 0xF) {
      0x0 -> 0x0 // M000
      0x1 -> 0x0 // M010
      0x2 -> 0x2 // M020
      0x3 -> 0x2 // M030
      0x4 -> 0x0 // E000
      0x5 -> 0x0 // E001
      0x6 -> 0x2 // E002
      0x7 -> 0x2 // E003
      0x8 -> 0x8 // M002
      0x9 -> 0x8 // M012
      0xA -> 0xA // M022
      0xB -> 0xA // M032
      0xC -> 0x8 // E020
      0xD -> 0x8 // E021
      0xE -> 0xA // E022
      0xF -> 0xA // E023
      else -> error(UNREACHABLE_MESSAGE)
    }
    return Pair(bankId or baseRegId, transpose)
  }

  fun mapBaseRegToModeMatrix3(varnode: Varnode): Pair<Int, Boolean> {
    val regId = regVarnodeToRegId(varnode)
    val bankId = regId and 0xF0
    val transpose = regId and 0b100 == 0b100
    val baseRegId = when (regId and 0xF) {
      0x0 -> 0x0 // M000
      0x1 -> 0x1 // M010
      0x2 -> 0x1 // M020
      0x3 -> 0x1 // M030
      0x4 -> 0x0 // E000
      0x5 -> 0x1 // E001
      0x6 -> 0x1 // E002
      0x7 -> 0x1 // E003
      0x8 -> 0x4 // M001
      0x9 -> 0x5 // M011
      0xA -> 0x5 // M021
      0xB -> 0x5 // M031
      0xC -> 0x4 // E010
      0xD -> 0x5 // E011
      0xE -> 0x5 // E012
      0xF -> 0x5 // E013
      else -> error(UNREACHABLE_MESSAGE)
    }
    return Pair(bankId or baseRegId, transpose)
  }

  fun mapBaseRegToModeMatrix4(varnode: Varnode, transpose: Boolean): Matrix4Mapper {
    val regId = regVarnodeToRegId(varnode)
    val bankId = regId and 0xF0
    val regTranspose = regId and 0b100 == 0b100
    val baseRegId = 0x0
    return Matrix4Mapper(bankId or baseRegId, regTranspose xor transpose)
  }

  fun regVarnodeToRegId(varnode: Varnode): Int {
    return ((varnode.offset - VFPU_REGS_START) / 4).toInt()
  }

  fun regIdToName(id: Int): String {
    return "V%02X".format(id)
  }
}
