package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp

class InjectVfpuWriteMatrix4(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val baseReg = con.inputlist[0]
    val row = con.inputlist[1].offset.toInt()

    val mapper = VfpuPcode.mapBaseRegToModeMatrix4(baseReg, transpose = false)

    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(mapper.elementAt(row, 0)), con.inputlist[2])
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(mapper.elementAt(row, 1)), con.inputlist[3])
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(mapper.elementAt(row, 2)), con.inputlist[4])
    pCode.emitAssignVarnodeToRegister(VfpuPcode.regIdToName(mapper.elementAt(row, 3)), con.inputlist[5])
    return pCode.emittedOps()
  }
}
