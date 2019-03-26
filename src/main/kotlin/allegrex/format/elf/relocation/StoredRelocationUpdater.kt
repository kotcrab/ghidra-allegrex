package allegrex.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfLoadHelper
import ghidra.app.util.bin.format.elf.relocation.AllegrexElfRelocationConstants
import ghidra.program.model.address.Address

class StoredRelocationUpdater {
    private val updates = mutableMapOf<Address, PendingUpdate>()

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
                val elfAddr = baseAddr.add(reloc.offset.toLong())
                val addr = baseAddr.add(reloc.offset.toLong()).add(reloc.relative.toLong())

                val instrValue = memory.getInt(addr)
                val instrBytes = ByteArray(4)
                memory.getBytes(addr, instrBytes)

                when (reloc.type) {
                    AllegrexElfRelocationConstants.R_MIPS_HI16 -> {
                        deferredHi16.add { linkedLoValue ->
                            val newReloc = AllegrexRelocation.fromElf(elfHeader, elfReloc, linkedLoValue)
                            updates[elfAddr] = PendingUpdate(newReloc, instrBytes)
                        }
                    }
                    AllegrexElfRelocationConstants.R_MIPS_LO16 -> {
                        deferredHi16.forEach { commit -> commit((instrValue and 0xFFFF).toShort().toInt()) }
                        updates[elfAddr] = PendingUpdate(reloc, instrBytes)
                        deferredHi16.clear()
                    }
                    else -> {
                        updates[elfAddr] = PendingUpdate(reloc, instrBytes)
                    }
                }
            }
        }
    }

    fun finalizeUpdate(loadHelper: ElfLoadHelper): Boolean {
        val tables = loadHelper.program.relocationTable
        val programRelocs = tables.relocations.asSequence().toList()
        programRelocs.forEach {
            tables.remove(it)
        }
        var allConverted = true
        programRelocs.forEach {
            val update = updates[it.address]
            if (update == null) {
                allConverted = false
                return@forEach
            }
            val allegrexReloc = update.reloc
            val newAddr = it.address.add(allegrexReloc.relative.toLong())
            tables.add(newAddr, allegrexReloc.type, allegrexReloc.toLongArray(), update.origInstr, it.symbolName)
        }
        return allConverted
    }

    class PendingUpdate(val reloc: AllegrexRelocation, val origInstr: ByteArray)
}
