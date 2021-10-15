package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.bridge.model.PpssppHleModule
import ghidra.dbg.target.TargetModule
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRangeImpl

@TargetObjectSchemaInfo(
  name = PpssppModelTargetModule.NAME,
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetModule(
  modules: PpssppModelTargetModuleContainer,
  module: PpssppHleModule
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetModuleContainer>(
    modules.model, modules, PathUtils.makeKey(PathUtils.makeIndex(module.address)), NAME
  ),
  TargetModule {

  companion object {
    const val NAME = "Module"
  }

  init {
    val startAddress: Address = getModel().addressFactory
      .defaultAddressSpace
      .getAddress(module.address.toString(16))
    val addressRange = AddressRangeImpl(startAddress, module.size)

    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to module.name,
        TargetModule.RANGE_ATTRIBUTE_NAME to addressRange,
        TargetModule.MODULE_NAME_ATTRIBUTE_NAME to module.name,
      ),
      "Initialized"
    )
  }
}
