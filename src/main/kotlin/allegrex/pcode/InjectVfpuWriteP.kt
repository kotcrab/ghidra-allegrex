package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuWriteP(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val baseReg = con.inputlist[0]

    val (baseRegId, stride) = VfpuPcode.mapBaseRegToModePair(baseReg)

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase)
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(baseRegId), con.inputlist[1])
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(baseRegId + stride), con.inputlist[2])
    return pCode.emittedOps()
  }
}
