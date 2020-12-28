package ghidra.app.util.bin.format.elf.relocation

import ghidra.app.util.bin.format.elf.ElfRelocation
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.StructureDataType

/** DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.  */
open class AllegrexElfRelocationExtension : ElfRelocation() {
  override fun getSymbolIndex(): Int {
    return 0
  }

  override fun getType(): Int {
    return (relocationInfo and 0xFF).toInt()
  }

  override fun toDataType(): DataType {
    val dtName = "Elf32_Allegrex_Rel"
    val struct = StructureDataType(CategoryPath("/ELF"), dtName, 0)
    struct.add(DWORD, "r_address", null)
    struct.add(BYTE, "r_type", null)
    struct.add(BYTE, "r_offsetIndex", null)
    struct.add(BYTE, "r_relocateToIndex", null)
    struct.add(BYTE, "r_unused", null)
    return struct
  }
}
