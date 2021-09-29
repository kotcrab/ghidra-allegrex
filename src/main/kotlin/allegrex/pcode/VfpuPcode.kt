package allegrex.pcode

import ghidra.program.model.pcode.Varnode

object VfpuPcode {
  private const val VFPU_REGS_START = 0x5000

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
      else -> error("This should be unreachable")
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
      else -> error("This should be unreachable")
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
      else -> error("This should be unreachable")
    }
    return Pair(bankId or baseRegId, stride)
  }

  fun regVarnodeToRegId(varnode: Varnode): Int {
    return ((varnode.offset - VFPU_REGS_START) / 4).toInt()
  }

  fun regIdToName(id: Int): String {
    return "V%02X".format(id)
  }
}
