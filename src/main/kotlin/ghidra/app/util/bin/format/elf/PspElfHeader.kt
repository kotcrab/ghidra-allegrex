package ghidra.app.util.bin.format.elf

import generic.continues.GenericFactory
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader
import ghidra.util.Msg
import org.apache.commons.lang3.reflect.FieldUtils

open class PspElfHeader : ElfHeader() {
  var useRebootBinTypeBMapping: Boolean = false
    private set

  override fun parse() {
    super.parse()
    parsePspRelocationTables()
  }

  private fun parsePspRelocationTables() {
    val relocTables = relocationTables.toMutableList()
    if (relocTables.isNotEmpty()) {
      Msg.info(this, "Relocation tables contains ${relocTables.size} sections before update.")
    }
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
            false, symbolTable, sectionToBeRelocated, ElfRelocationTable.TableFormat.DEFAULT
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

  private fun initOptions(useRebootBinTypeBMapping: Boolean) {
    this.useRebootBinTypeBMapping = useRebootBinTypeBMapping
  }

  override fun e_machine(): Short {
    return PspElfConstants.EM_MIPS_PSP_HACK
  }

  companion object {
    fun createElfHeader(factory: GenericFactory, provider: ByteProvider, useRebootBinTypeBMapping: Boolean): PspElfHeader {
      val elfHeader = factory.create(PspElfHeader::class.java) as PspElfHeader
      elfHeader.initElfHeader(factory, provider)
      elfHeader.initOptions(useRebootBinTypeBMapping)
      return elfHeader
    }
  }
}
