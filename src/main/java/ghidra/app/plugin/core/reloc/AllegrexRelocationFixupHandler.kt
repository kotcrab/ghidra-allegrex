package ghidra.app.plugin.core.reloc

import com.kotcrab.ghidra.allegrex.format.elf.MipsInstructionStasher
import ghidra.app.util.bin.format.elf.relocation.Allegrex_ElfRelocationConstants
import ghidra.app.util.opinion.PspElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.lang.Processor
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.reloc.Relocation
import ghidra.program.model.util.CodeUnitInsertionException

class AllegrexRelocationFixupHandler : RelocationFixupHandler() {
    override fun handlesProgram(program: Program): Boolean {
        if (PspElfLoader.PSP_ELF_NAME != program.executableFormat) {
            return false
        }
        val language = program.language
        if (language.languageDescription.size != 32) {
            return false
        }
        val processor = language.processor
        return processor == Processor.findOrPossiblyCreateProcessor("Allegrex")
    }
    @Throws(MemoryAccessException::class, CodeUnitInsertionException::class)
    override fun processRelocation(
        program: Program,
        relocation: Relocation,
        oldImageBase: Address,
        newImageBase: Address
    ): Boolean {
        val memory = program.memory
        val diff = newImageBase.subtract(oldImageBase).toInt()
        val address = relocation.address
        val value = memory.getInt(address)
        var newValue = 0
        when (relocation.type) {
            Allegrex_ElfRelocationConstants.R_MIPS_NONE -> {
                newValue = value
            }
            Allegrex_ElfRelocationConstants.R_MIPS_16 -> {
                newValue = relocate(value, 0xFFFF, diff)
            }
            Allegrex_ElfRelocationConstants.R_MIPS_32 -> {
                newValue += diff
            }
            Allegrex_ElfRelocationConstants.R_MIPS_26 -> {
                newValue = relocate(value, 0x3FFFFFF, diff shr 2)
            }
            Allegrex_ElfRelocationConstants.R_MIPS_HI16 -> {
                // TODO this won't really work for cases when sign on LO part changes (probably), might need deferring
                newValue = relocate(value, 0xFFFF, diff shr 16)
            }
            Allegrex_ElfRelocationConstants.R_MIPS_LO16 -> {
                newValue = relocate(value, 0xFFFF, diff)
            }
            else -> return false
        }
        if (newValue == 0) return false
        val instructionStasher = MipsInstructionStasher(program, address)
        memory.setInt(address, newValue)
        instructionStasher.restore()
        return true
    }

    private fun relocate(data: Int, mask: Int, relocateTo: Int): Int {
        return (data and mask.inv()) or (((data and mask) + relocateTo) and mask)
    }
}
