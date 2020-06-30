package allegrex.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfLoadHelper
import ghidra.app.util.bin.format.elf.relocation.AllegrexElfRelocationConstants
import ghidra.program.model.address.Address
import ghidra.util.Msg

class StoredRelocationUpdater {
    private val updates = mutableListOf<PendingUpdate>()

    fun resetAndCollectForUpdate(loadHelper: ElfLoadHelper) {
        reset()
        collectForUpdate(loadHelper)
    }

    private fun reset() {
        updates.clear()
    }

    private fun collectForUpdate(loadHelper: ElfLoadHelper) {
        val program = loadHelper.program
        val memory = program.memory
        val elfHeader = loadHelper.elfHeader
        val elfTables = elfHeader.relocationTables
        val baseAddr = program.imageBase

        elfTables.forEach { table ->
            val deferredHi16 = mutableListOf<(loValue: Int) -> Unit>()

            table.relocations.forEach { elfReloc ->
                val reloc = AllegrexRelocation.fromElf(elfHeader, elfReloc, 0)
                val addr = baseAddr.add(reloc.offset.toLong()).add(reloc.relative.toLong())

                val instrValue = memory.getInt(addr)
                val instrBytes = ByteArray(4)
                memory.getBytes(addr, instrBytes)

                when (reloc.type) {
                    AllegrexElfRelocationConstants.R_MIPS_HI16 -> {
                        deferredHi16.add { linkedLoValue ->
                            val newReloc = AllegrexRelocation.fromElf(elfHeader, elfReloc, linkedLoValue)
                            updates.add(PendingUpdate(addr, newReloc, instrBytes))
                        }
                    }
                    AllegrexElfRelocationConstants.R_MIPS_LO16 -> {
                        deferredHi16.forEach { commit -> commit((instrValue and 0xFFFF).toShort().toInt()) }
                        updates.add(PendingUpdate(addr, reloc, instrBytes))
                        deferredHi16.clear()
                    }
                    else -> {
                        updates.add(PendingUpdate(addr, reloc, instrBytes))
                    }
                }
            }

            if (deferredHi16.size != 0) {
                Msg.warn(this, "Failed to update some deferred R_MIPS_HI16 relocations")
            }
        }
    }

    fun finalizeUpdate(loadHelper: ElfLoadHelper): Boolean {
        val table = loadHelper.program.relocationTable
        table.relocations
            .asSequence()
            .toList()
            .forEach {
                table.remove(it)
            }
        var conflict = false
        updates.forEach { update ->
            val allegrexReloc = update.reloc
            if (table.getRelocation(update.address) != null) {
                Msg.warn(this, "Duplicate relocation at ${update.address}")
                conflict = true
            }
            table.add(update.address, allegrexReloc.type, allegrexReloc.toLongArray(), update.origInstr, null)
        }
        return conflict
    }

    class PendingUpdate(
        val address: Address,
        val reloc: AllegrexRelocation,
        val origInstr: ByteArray
    )
}
