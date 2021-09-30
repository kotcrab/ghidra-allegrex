package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectContext
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

class InjectVfpuReadMatrix4(
  sourceName: String,
  private val language: SleighLanguage,
  private val uniqueBase: Long,
  private val maxUniqueBase: Long,
) : InjectPayloadCallother(sourceName) {
  override fun getPcode(program: Program, con: InjectContext): Array<PcodeOp> {
    val output = con.output[0]
    val baseReg = con.inputlist[0]
    val transpose = con.inputlist[1].offset.toInt() != 0

    val mapper = VfpuPcode.mapBaseRegToModeMatrix4(baseReg, transpose)
    val pCode = PcodeOpEmitter(language, con.baseAddr, uniqueBase, maxUniqueBase)

    var currentSize = 8
    fun nextVarnode(): Varnode {
      val vn = pCode.getOrDefineVarnode("tmp$currentSize", currentSize)
      currentSize += 4
      return vn
    }

    var currentVarnode = nextVarnode()
    pCode.emitPieceRegisters(
      currentVarnode,
      VfpuPcode.regIdToName(mapper.elementAt(3, 3)),
      VfpuPcode.regIdToName(mapper.elementAt(3, 2))
    )
    repeat(4) { i ->
      repeat(4) next@{ ii ->
        val row = (3 - i)
        val column = (3 - ii)
        if ((row == 3 && column == 3) || (row == 3 && column == 2)) {
          return@next
        }
        val prevVarnode = currentVarnode
        currentVarnode = nextVarnode()
        pCode.emitPieceVarnodeRegister(currentVarnode, prevVarnode, VfpuPcode.regIdToName(mapper.elementAt(row, column)))
      }
    }
    pCode.emitAssignVarnodeToVarnode(output, currentVarnode)
    return pCode.emittedOps()
  }
}
