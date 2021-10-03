package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuLoadQPart(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
  private val vfpuPcode: VfpuPcode = DefaultVfpuPcode
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val baseReg = con.inputlist[0]
    val columnMode = con.inputlist[1].offset == 0L
    val part = con.inputlist[2].offset.toInt()
    val value = con.inputlist[3]

    val baseRegId = vfpuPcode.regVarnodeToRegId(baseReg)
    val mapper = VectorMapper(baseRegId, !columnMode, 4, vfpuPcode)

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    pCode.emitAssignVarnodeToRegister(mapper.regNameAt(part), value)
    return pCode.emittedOps()
  }
}
