package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppMemoryRange
import ghidra.dbg.target.TargetMemoryRegion
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRangeImpl

@TargetObjectSchemaInfo(
  name = PpssppModelTargetMemoryRegion.NAME,
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetMemoryRegion(
  memory: PpssppModelTargetProcessMemory,
  range: PpssppMemoryRange
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetProcessMemory>(
    memory.model, memory, PathUtils.makeKey(range.address.toString(16)), NAME
  ),
  TargetMemoryRegion {

  companion object {
    const val NAME = "MemoryRegion"
  }

  init {
    val startAddress: Address = getModel().addressFactory
      .defaultAddressSpace
      .getAddress(range.address.toString(16))
    val addressRange = AddressRangeImpl(startAddress, range.size)

    changeAttributes(
      listOf(),
      mapOf(
        TargetMemoryRegion.MEMORY_ATTRIBUTE_NAME to memory,
        TargetMemoryRegion.RANGE_ATTRIBUTE_NAME to addressRange,
        TargetMemoryRegion.READABLE_ATTRIBUTE_NAME to true,
        TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME to true,
        TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME to true,
        TargetObject.DISPLAY_ATTRIBUTE_NAME to range.name
      ),
      UpdateReason.INITIALIZED
    )
  }
}
