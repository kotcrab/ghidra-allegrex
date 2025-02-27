package allegrex.export

import allegrex.export.ExportElf.SectionName.COMBINED_0
import allegrex.export.ExportElf.SectionName.COMBINED_1
import allegrex.export.ExportElf.SectionName.REL_COMBINED_0
import allegrex.export.ExportElf.SectionName.REL_COMBINED_1
import allegrex.export.ExportElf.SectionName.SHSTRTAB
import allegrex.export.ExportElf.SectionName.STRTAB
import allegrex.export.ExportElf.SectionName.SYMTAB
import allegrex.util.LeRandomAccessFile
import allegrex.util.align
import allegrex.util.writeString
import java.io.ByteArrayOutputStream
import java.io.File

object ExportElf {
  fun writeElf(
    outFile: File,
    sections: List<Section>,
    shStrTab: StringAllocator,
    symbols: List<Symbol>,
    strTab: StringAllocator,
    programBytes: List<ByteArray>,
    programRelocations: List<List<AllegrexRelocation>>,
  ) {
    LeRandomAccessFile(outFile).use {
      it.setLength(0)
      // 0x00
      it.writeByte(0x7F) // magic number
      it.writeString("ELF")
      it.write(byteArrayOf(0x01, 0x01, 0x01, 0x00)) // 32-bit, little-endian, version 1, ABI none
      it.writeInt(0)
      it.writeInt(0)

      // 0x10
      it.writeShort(0x01) // ET_REL
      it.writeShort(0x08) // MIPS
      it.writeInt(1) // version 1
      it.writeInt(0) // entry point offset
      it.writeInt(0) // program headers offset

      // 0x20
      val sectionHeaderOffset = it.filePointer
      it.writeInt(0) // section header offset (written later)
      it.writeInt(0x10A23001) // flags
      it.writeShort(0x34) // header size
      it.writeShort(0) // program header size
      it.writeShort(0) // program header count
      it.writeShort(0x28) // section header size

      // 0x30
      it.writeShort(sections.size)
      it.writeShort(sections.indexOfFirst { e -> shStrTab.lookupOrNull(e.name) == ".shstrtab" })

      // 0x34
      // Write program bytes
      val programBytesOffsets = programBytes.map { bytes ->
        val start = it.filePointer
        it.write(bytes)
        it.align(4)
        start
      }

      // Write relocations
      val programRelocationsOffsets = programRelocations.map { relocations ->
        val start = it.filePointer
        relocations.forEach { relocation ->
          it.writeRelocation(relocation)
        }
        it.align(4)
        start
      }

      // Write symbols
      val symTabStart = it.filePointer
      symbols.forEach { symbol ->
        it.writeSymbol(symbol)
      }
      it.align(4)

      // Write strtab
      val strTabStart = it.filePointer
      val strTabBytes = strTab.toByteArray()
      it.write(strTabBytes)
      it.align(4)

      // Write shstrtab
      val shStrTabStart = it.filePointer
      val shStrTabBytes = shStrTab.toByteArray()
      it.write(shStrTabBytes)
      it.align(4)

      // Write sections
      val sectionsStart = it.filePointer

      it.seek(sectionHeaderOffset)
      it.writeInt(sectionsStart.toInt())
      it.seek(sectionsStart)

      sections.forEach { section ->
        it.writeInt(section.name)
        it.writeInt(section.type)
        it.writeInt(section.flags)
        it.writeInt(section.address)

        if (section.offset == -1) {
          it.writeInt(
            when (shStrTab.lookupOrNull(section.name)) {
              COMBINED_0 -> programBytesOffsets[0]
              COMBINED_1 -> programBytesOffsets[1]
              REL_COMBINED_0 -> programRelocationsOffsets[0]
              REL_COMBINED_1 -> programRelocationsOffsets[1]
              SYMTAB -> symTabStart
              STRTAB -> strTabStart
              SHSTRTAB -> shStrTabStart
              else -> error("Unknown section: ${section.name}")
            }.toInt()
          )
        } else {
          it.writeInt(section.offset)
        }

        if (section.size == -1) {
          it.writeInt(
            when (shStrTab.lookupOrNull(section.name)) {
              COMBINED_0 -> programBytes[0].size
              COMBINED_1 -> programBytes[1].size
              REL_COMBINED_0 -> programRelocations[0].size * 8
              REL_COMBINED_1 -> programRelocations[1].size * 8
              SYMTAB -> symbols.size * 0x10
              STRTAB -> strTabBytes.size
              SHSTRTAB -> shStrTabBytes.size
              else -> error("Unknown section: ${section.name}")
            }.toInt()
          )
        } else {
          it.writeInt(section.size)
        }

        it.writeInt(section.link)
        it.writeInt(section.info)
        it.writeInt(section.addressAlign)
        it.writeInt(section.entrySize)
      }
    }
  }

  private fun LeRandomAccessFile.writeRelocation(relocation: AllegrexRelocation) {
    writeInt(relocation.offset)
    writeByte(relocation.type)
    writeByte(relocation.symbol)
    writeByte(relocation.symbol shr 8)
    writeByte(relocation.symbol shr 16)
  }

  private fun LeRandomAccessFile.writeSymbol(symbol: Symbol) {
    writeInt(symbol.name)
    writeInt(symbol.value)
    writeInt(symbol.size)
    writeByte(symbol.info.toInt())
    writeByte(symbol.other.toInt())
    writeShort(symbol.sectionIndex)
  }

  object SectionName {
    const val COMBINED_0 = ".combined0"
    const val REL_COMBINED_0 = ".rel.combined0"
    const val COMBINED_1 = ".combined1"
    const val REL_COMBINED_1 = ".rel.combined1"
    const val SYMTAB = ".symtab"
    const val STRTAB = ".strtab"
    const val SHSTRTAB = ".shstrtab"
  }

  object Const {
    const val SHT_PROGBITS = 0x1
    const val SHT_SYMTAB = 0x2
    const val SHT_STRTAB = 0x3
    const val SHT_REL = 0x9

    const val SHF_WRITE = 0x1
    const val SHF_ALLOC = 0x2
    const val SHF_EXECINSTR = 0x4
    const val SHF_INFO_LINK = 0x40

    const val STB_LOCAL = 0x0 shl 4
    const val STB_GLOBAL = 0x1 shl 4
    const val STB_WEAK = 0x2 shl 4

    const val STT_NOTYPE = 0x0
    const val STT_FUNC = 0x2
    const val STT_SECTION = 0x3
  }

  class StringAllocator {
    private val cache = mutableMapOf<String, Int>()
    private val bytes = ByteArrayOutputStream()

    init {
      getOrPut("")
    }

    fun getOrPut(text: String): Int {
      return cache.getOrPut(text) {
        val pos = bytes.size()
        bytes.write(text.toByteArray(Charsets.US_ASCII))
        bytes.write(byteArrayOf(0))
        pos
      }
    }

    fun lookup(offset: Int): String {
      return lookupOrNull(offset)
        ?: error("Can't find string in table for offset: $offset")
    }

    fun lookupOrNull(offset: Int): String? {
      return cache.entries.firstOrNull { it.value == offset }?.key
    }

    fun toByteArray(): ByteArray {
      return bytes.toByteArray()
    }
  }

  data class AllegrexRelocation(
    val offset: Int,
    val type: Int,
    val symbol: Int,
  )

  data class Symbol(
    val name: Int,
    val value: Int,
    val size: Int,
    val info: Byte,
    val other: Byte,
    val sectionIndex: Int
  )

  data class Section(
    val name: Int,
    val type: Int,
    val flags: Int,
    val address: Int,
    val offset: Int,
    val size: Int,
    val link: Int,
    val info: Int,
    val addressAlign: Int,
    val entrySize: Int,
  )
}
