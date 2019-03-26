package allegrex

import allegrex.MipsInstructionStasher.LinkedCuRestorePolicy.*
import ghidra.program.model.address.Address
import ghidra.program.model.lang.InstructionPrototype
import ghidra.program.model.lang.ProgramProcessorContext
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.DumbMemBufferImpl
import ghidra.program.model.symbol.Reference
import ghidra.program.model.symbol.SourceType

class MipsInstructionStasher(private val program: Program, private val address: Address) {
    private var cuCtx: CodeUnitCtx? = null
    private var linkedCuCtx: CodeUnitCtx? = null
    private var linkedCuRestorePolicy = Ignore

    init {
        clearAndSave()
    }

    private fun clearAndSave() {
        cuCtx = CodeUnitCtx.fromProgram(program, address)
        cuCtx?.also {
            if (it.prototype.hasDelaySlots()) {
                linkedCuCtx =
                    CodeUnitCtx.fromProgram(program, address.add(4))
                linkedCuRestorePolicy = RestoreFirst
            } else if (it.prototype.isInDelaySlot) {
                linkedCuCtx = CodeUnitCtx.fromProgram(program, address.subtract(4))
                linkedCuRestorePolicy = RestoreLast
            }
            it.clear()
        }
    }

    fun restore() {
        cuCtx?.also { ctx ->
            if (linkedCuRestorePolicy == RestoreFirst) {
                linkedCuCtx?.restore()
            }
            ctx.restore()
            if (linkedCuRestorePolicy == RestoreLast) {
                linkedCuCtx?.restore()
            }
        }
    }

    private enum class LinkedCuRestorePolicy {
        Ignore, RestoreFirst, RestoreLast
    }
}

private class CodeUnitCtx(
    val program: Program,
    val minAddress: Address,
    val maxAddress: Address,
    val prototype: InstructionPrototype,
    val referencesFrom: Array<Reference>
) {
    companion object {
        fun fromProgram(program: Program, address: Address): CodeUnitCtx? {
            val instruction = program.listing.getInstructionContaining(address) ?: return null
            return CodeUnitCtx(
                program,
                instruction.minAddress, instruction.maxAddress,
                instruction.prototype, instruction.referencesFrom
            )
        }
    }

    fun clear() {
        program.listing.clearCodeUnits(minAddress, maxAddress, false)
    }

    fun restore() {
        val buf = DumbMemBufferImpl(program.memory, minAddress)
        val context = ProgramProcessorContext(program.programContext, minAddress)
        program.listing.createInstruction(minAddress, prototype, buf, context)
        for (reference in referencesFrom) {
            if (reference.source != SourceType.DEFAULT) {
                program.referenceManager.addReference(reference)
            }
        }
    }
}
