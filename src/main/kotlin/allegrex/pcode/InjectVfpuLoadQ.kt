package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuLoadQ(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
  private val vfpuPcode: VfpuPcode = DefaultVfpuPcode
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    var input = 0
    val baseReg = con.inputlist[input++]
    val columnMode = con.inputlist[input++].offset == 0L

    val baseRegId = vfpuPcode.regVarnodeToRegId(baseReg)
    val mapper = VectorMapper(baseRegId, !columnMode, 4, vfpuPcode)

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    repeat(mapper.size) { i ->
      pCode.emitAssignVarnodeToRegister(mapper.regNameAt(i), con.inputlist[input++])
    }
    return pCode.emittedOps()
  }
}
