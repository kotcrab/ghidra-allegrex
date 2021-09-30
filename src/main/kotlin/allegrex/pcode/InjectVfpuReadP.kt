package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuReadP(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val output = con.output[0]
    val baseReg = con.inputlist[0]

    val (baseRegId, stride) = VfpuPcode.mapBaseRegToModePair(baseReg)

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    pCode.emitPieceRegisters(output, VfpuPcode.regIdToName(baseRegId + stride), VfpuPcode.regIdToName(baseRegId))
    return pCode.emittedOps()
  }
}
