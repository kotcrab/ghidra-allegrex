package com.kotcrab.ghidra.allegrex.format.elf

import com.kotcrab.ghidra.allegrex.format.elf.relocation.AllegrexRelocation
import ghidra.app.util.bin.format.elf.ElfLoadHelper

class UpdateRelocationTable {
    fun update(elfLoadHelper: ElfLoadHelper): Boolean {
        val memory = elfLoadHelper.program.memory
        val elfHeader = elfLoadHelper.elfHeader
        val elfTables = elfHeader.relocationTables
        val allegrexRelocs = elfTables
            .flatMap { elfTable ->
                elfTable.relocations.map { AllegrexRelocation.fromElf(elfHeader, it) }
            }
            .associateBy({ it.offset }, { it })
        val tables = elfLoadHelper.program.relocationTable
        val programRelocs = tables.relocations.asSequence().toList()
        programRelocs.forEach {
            tables.remove(it)
        }
        var allConverted = true
        programRelocs.forEach {
            val allegrexReloc = allegrexRelocs.get(it.address.offset.toInt())
            if (allegrexReloc == null) {
                allConverted = false
                return@forEach
            }
            val newAddr = it.address.add(allegrexReloc.relative.toLong())
            // TODO this isn't right, it will get instruction after relocation
            val instrBytes = ByteArray(4)
            memory.getBytes(newAddr, instrBytes)
            tables.add(newAddr, allegrexReloc.type, allegrexReloc.toLongArray(), instrBytes, it.symbolName)
        }
        return allConverted
    }
}
