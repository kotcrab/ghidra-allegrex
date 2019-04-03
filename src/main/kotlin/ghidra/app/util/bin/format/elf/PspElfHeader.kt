package ghidra.app.util.bin.format.elf

import generic.continues.GenericFactory
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader
import ghidra.util.Msg
import org.apache.commons.lang3.reflect.FieldUtils

open class PspElfHeader : ElfHeader() {
    override fun parse() {
        super.parse()
        parsePspRelocationTables()
    }

    private fun parsePspRelocationTables() {
        val relocTables = relocationTables.toMutableList()
        for (section in sections) {
            parsePspSectionBasedRelocationTable(section, relocTables)
        }
        try {
            FieldUtils.writeField(this, "relocationTables", relocTables.toTypedArray(), true)
        } catch (e: IllegalAccessException) {
            Msg.error(this, "Failed to update PSP ELF relocation table list: ${e.message}, ${e.javaClass.simpleName}")
            e.printStackTrace()
        }
    }

    private fun parsePspSectionBasedRelocationTable(
        section: ElfSectionHeader,
        relocTableList: MutableList<ElfRelocationTable>
    ) {
        try {
            val sectionHeaderType = section.type
            if (sectionHeaderType == PspElfConstants.SHT_PSP_REL) {
                val link = section.link // section index of associated symbol table
                val info = section.info // section index of section to which relocations apply (relocation offset base)
                val sectionToBeRelocated = if (info != 0) sections[info] else null
                val relocBaseName = if (sectionToBeRelocated != null) sectionToBeRelocated.nameAsString else "PT_LOAD"
                val symbolTable = getSymbolTable(sections[link]) ?: createDummySymbolTable(reader, sections[link])
                Msg.debug(this, "PSP ELF relocation table section ${section.nameAsString} affecting $relocBaseName")
                relocTableList.add(
                    ElfRelocationTable.createElfRelocationTable(
                        reader as FactoryBundledWithBinaryReader, this,
                        section, section.offset, section.address, section.size, section.entrySize,
                        false, symbolTable, sectionToBeRelocated
                    )
                )
            }
        } catch (e: ArrayIndexOutOfBoundsException) {
            Msg.error(this, "Failed to process PSP relocation section ${section.nameAsString}: ${e.message}")
        }
    }

    private fun createDummySymbolTable(reader: BinaryReader, header: ElfSectionHeader): ElfSymbolTable {
        Msg.debug(this, "ELF symbol table missing, creating dummy symbol table")
        val stringTable = ElfStringTable.createElfStringTable(
            reader as FactoryBundledWithBinaryReader, this, header, 0, 0, 0
        )
        return ElfSymbolTable.createElfSymbolTable(
            reader, this, header, 0, 0, 1, 1, stringTable, false
        )
    }

    override fun e_machine(): Short {
        return PspElfConstants.EM_MIPS_PSP_HACK
    }

    companion object {
        fun createElfHeader(factory: GenericFactory, provider: ByteProvider): PspElfHeader {
            val elfHeader = factory.create(PspElfHeader::class.java) as PspElfHeader
            elfHeader.initElfHeader(factory, provider)
            return elfHeader
        }
    }
}
