package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

class InjectVfpuReadVector(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
  private val createMapper: (VfpuPcode, Varnode) -> VectorMapper,
  private val vfpuPcode: VfpuPcode = DefaultVfpuPcode
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp>? {
    val output = con.output[0]
    val baseReg = con.inputlist[0]
    if (!baseReg.isRegister) {
      return null
    }

    val mapper = createMapper(vfpuPcode, baseReg)
    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    val varnodeProvider = TempVarnodeProvider(pCode)

    var currentVarnode = varnodeProvider.nextVarnode()
    pCode.emitPieceRegisters(
      currentVarnode,
      mapper.regNameAt(mapper.lastIndex),
      mapper.regNameAt(mapper.lastIndex - 1),
    )
    repeat(mapper.size) { i ->
      val index = (mapper.lastIndex - i)
      if (index == mapper.lastIndex || index == mapper.lastIndex - 1) {
        return@repeat
      }
      val prevVarnode = currentVarnode
      currentVarnode = varnodeProvider.nextVarnode()
      pCode.emitPieceVarnodeRegister(currentVarnode, prevVarnode, mapper.regNameAt(index))
    }
    pCode.emitAssignVarnodeToVarnode(output, currentVarnode)
    return pCode.emittedOps()
  }
}
