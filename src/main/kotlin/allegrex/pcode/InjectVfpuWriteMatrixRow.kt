package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

class InjectVfpuWriteMatrixRow(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
  private val createMapper: (VfpuPcode, Varnode, Boolean) -> MatrixMapper,
  private val vfpuPcode: VfpuPcode = DefaultVfpuPcode
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    var input = 0
    val baseReg = con.inputlist[input++]
    val row = con.inputlist[input++].offset.toInt()

    val mapper = createMapper(vfpuPcode, baseReg, false) // write is always transpose = false
    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    repeat(mapper.dimSize) { i ->
      pCode.emitAssignVarnodeToRegister(mapper.regNameAt(row, i), con.inputlist[input++])
    }
    return pCode.emittedOps()
  }
}
