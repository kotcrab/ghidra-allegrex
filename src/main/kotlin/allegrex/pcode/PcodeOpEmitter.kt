package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Register
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

class PcodeOpEmitter(
  private val language: SleighLanguage,
  private val opAddress: Address,
  private var uniqueBase: Long,
  private val maxUniqueBase: Long
) {
  private val uniqueSpace = language.addressFactory.uniqueSpace
  private val nameToVarnode: MutableMap<String, Varnode> = mutableMapOf()
  private val opList: MutableList<PcodeOp> = mutableListOf()
  private var seqNum = 0

  private fun findRegister(name: String): Varnode {
    var vn = nameToVarnode[name]
    if (vn != null) {
      return vn
    }
    val reg = language.getRegister(name)
      ?: throw IllegalArgumentException("Register must already exist: $name")
    vn = convertRegisterToVarnode(reg)
    nameToVarnode[name] = vn
    return vn
  }

  fun getOrDefineVarnode(name: String, size: Int): Varnode {
    val vn = nameToVarnode[name]
    if (vn != null) {
      require(vn.size == size) { "Varnode size mismatch: $name, ${vn.size} != $size" }
      return vn
    }
    val reg = language.getRegister(name)
    require(reg == null) { "Varnode name conflicts with existing register: $name" }
    return defineVarnode(name, size)
  }

  private fun defineVarnode(name: String, size: Int): Varnode {
    val vn = Varnode(uniqueSpace.getAddress(uniqueBase), size)
    uniqueBase += size
    if (uniqueBase > maxUniqueBase) {
      error("Reserved unique space overflow")
    }
    nameToVarnode[name] = vn
    return vn
  }

  private fun convertRegisterToVarnode(reg: Register): Varnode {
    return Varnode(reg.address, reg.bitLength / 8)
  }

  fun emitAssignVarnodeToRegister(register: String, varnode: Varnode) {
    opList.add(
      PcodeOp(
        opAddress, seqNum++, PcodeOp.COPY,
        arrayOf(varnode),
        findRegister(register)
      )
    )
  }

  fun emitAssignRegisterToVarnode(varnode: Varnode, register: String) {
    opList.add(
      PcodeOp(
        opAddress, seqNum++, PcodeOp.COPY,
        arrayOf(findRegister(register)),
        varnode
      )
    )
  }

  fun emitAssignVarnodeToVarnode(varnode1: Varnode, varnode2: Varnode) {
    opList.add(
      PcodeOp(
        opAddress, seqNum++, PcodeOp.COPY,
        arrayOf(varnode2),
        varnode1
      )
    )
  }

  fun emitPieceRegisters(outVarnode: Varnode, in1: String, in2: String) {
    val in1Reg = findRegister(in1)
    val in2Reg = findRegister(in2)
    opList.add(
      PcodeOp(
        opAddress, seqNum++, PcodeOp.PIECE,
        arrayOf(in1Reg, in2Reg),
        outVarnode
      )
    )
  }

  fun emitPieceVarnodeRegister(outVarnode: Varnode, in1: Varnode, in2: String) {
    val in2Reg = findRegister(in2)
    opList.add(
      PcodeOp(
        opAddress, seqNum++, PcodeOp.PIECE,
        arrayOf(in1, in2Reg),
        outVarnode
      )
    )
  }

  fun emittedOps(): Array<PcodeOp> {
    return opList.toTypedArray()
  }
}
