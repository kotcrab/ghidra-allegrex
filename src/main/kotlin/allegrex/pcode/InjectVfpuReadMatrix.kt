package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

class InjectVfpuReadMatrix(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
  private val createMapper: (VfpuPcode, Varnode, Boolean) -> MatrixMapper,
  private val vfpuPcode: VfpuPcode = DefaultVfpuPcode
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val output = con.output[0]
    val baseReg = con.inputlist[0]
    val transpose = con.inputlist[1].offset.toInt() != 0

    val mapper = createMapper(vfpuPcode, baseReg, transpose)
    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)
    val varnodeProvider = TempVarnodeProvider(pCode)

    var currentVarnode = varnodeProvider.nextVarnode()
    pCode.emitPieceRegisters(
      currentVarnode,
      mapper.regNameAt(mapper.lastDimIndex, mapper.lastDimIndex),
      mapper.regNameAt(mapper.lastDimIndex, mapper.lastDimIndex - 1)
    )
    repeat(mapper.dimSize) { i ->
      repeat(mapper.dimSize) next@{ ii ->
        val row = (mapper.lastDimIndex - i)
        val column = (mapper.lastDimIndex - ii)
        if ((row == mapper.lastDimIndex && column == mapper.lastDimIndex) || (row == mapper.lastDimIndex && column == mapper.lastDimIndex - 1)) {
          return@next
        }
        val prevVarnode = currentVarnode
        currentVarnode = varnodeProvider.nextVarnode()
        pCode.emitPieceVarnodeRegister(currentVarnode, prevVarnode, mapper.regNameAt(row, column))
      }
    }
    pCode.emitAssignVarnodeToVarnode(output, currentVarnode)
    return pCode.emittedOps()
  }
}
