package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppHleFunction
import ghidra.dbg.attributes.TargetDataType
import ghidra.dbg.target.TargetNamedDataType
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetSymbol
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils
import ghidra.program.model.address.Address

@TargetObjectSchemaInfo(
  name = PpssppModelTargetSymbol.NAME,
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetSymbol(
  namespace: PpssppModelTargetSymbolContainer,
  function: PpssppHleFunction
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetSymbolContainer>(
    namespace.model, namespace, PathUtils.makeKey(PathUtils.makeIndex(function.address)), NAME
  ),
  TargetSymbol {

  companion object {
    const val NAME = "Symbol"
  }

  init {
    val address: Address = getModel().addressFactory
      .defaultAddressSpace
      .getAddress(function.address.toString(16))

    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to function.name,
        TargetObject.VALUE_ATTRIBUTE_NAME to address,
        TargetSymbol.SIZE_ATTRIBUTE_NAME to 4L,
        TargetSymbol.NAMESPACE_ATTRIBUTE_NAME to namespace,
      ),
      "Initialized"
    )
  }
}
