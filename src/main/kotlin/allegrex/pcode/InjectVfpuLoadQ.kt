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
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val baseReg = con.inputlist[0]
    val columnMode = con.inputlist[1].offset == 0L
    val value1 = con.inputlist[2]
    val value2 = con.inputlist[3]
    val value3 = con.inputlist[4]
    val value4 = con.inputlist[5]

    val baseRegId = VfpuPcode.regVarnodeToRegId(baseReg)
    val stride = if (columnMode) 4 else 1

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(baseRegId), value1)
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(baseRegId + stride), value2)
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(baseRegId + stride * 2), value3)
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(baseRegId + stride * 3), value4)
    return pCode.emittedOps()
  }
}
