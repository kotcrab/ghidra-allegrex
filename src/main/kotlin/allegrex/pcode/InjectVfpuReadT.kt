package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuReadT(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val output = con.output[0]
    val baseReg = con.inputlist[0]

    val (baseRegId, stride) = VfpuPcode.mapBaseRegToModeTriple(baseReg)

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    val tmp8 = pCode.getOrDefineVarnode("tmp8", 8)
    pCode.emitPieceRegisters(tmp8, VfpuPcode.regIdToName(baseRegId + stride * 2), VfpuPcode.regIdToName(baseRegId + stride))
    pCode.emitPieceVarnodeRegister(output, tmp8, VfpuPcode.regIdToName(baseRegId))
    return pCode.emittedOps()
  }
}
