package allegrex.pcode

import ghidra.program.model.pcode.Varnode

class TempVarnodeProvider(
  private val pCode: PcodeOpEmitter,
  initialSize: Int = 8,
  private val growSize: Int = 4
) {
  var currentSize = initialSize

  fun nextVarnode(): Varnode {
    val vn = pCode.getOrDefineVarnode("tmp$currentSize", currentSize)
    currentSize += growSize
    return vn
  }
}
