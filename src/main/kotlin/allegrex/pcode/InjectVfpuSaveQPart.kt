package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuSaveQPart(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val output = con.output[0]
    val baseReg = con.inputlist[0]
    val columnMode = con.inputlist[1].offset == 0L
    val part = con.inputlist[2].offset.toInt()

    val baseRegId = VfpuPcode.regVarnodeToRegId(baseReg)
    val stride = if (columnMode) 4 else 1

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase)
    pCode.emitAssignRegisterToVarnode(output, VfpuPcode.regIdToName(baseRegId + stride * part))
    return pCode.emittedOps()
  }
}
