package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppCpuRegisterMeta
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetRegister
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils
import java.math.BigInteger

@TargetObjectSchemaInfo(
  name = "RegisterDescriptor",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetRegister(
  registers: PpssppModelTargetRegisterContainerAndBank,
  private val registerMeta: PpssppCpuRegisterMeta
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetRegisterContainerAndBank>(
    registers.model, registers, PathUtils.makeKey(registerMeta.name), "Register"
  ),
  TargetRegister {

  init {
    changeAttributes(
      listOf(),
      listOf(),
      mapOf(
        TargetRegister.CONTAINER_ATTRIBUTE_NAME to registers,
        TargetRegister.LENGTH_ATTRIBUTE_NAME to registerMeta.bitLength,
        TargetObject.DISPLAY_ATTRIBUTE_NAME to "[${registerMeta.name}]",
      ),
      UpdateReason.INITIALIZED
    )
  }

  fun updateValue(value: ByteArray) {
    val hexValue = BigInteger(1, value).toString(16)
    changeAttributes(
      emptyList(), emptyList(), mapOf(
        TargetRegister.VALUE_ATTRIBUTE_NAME to hexValue,
        TargetRegister.DISPLAY_ATTRIBUTE_NAME to "${registerMeta.name}: $hexValue",
      ),
      UpdateReason.REFRESHED
    )
  }
}
