package allegrex.agent.ppsspp.model

import ghidra.dbg.target.TargetEnvironment
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

@TargetObjectSchemaInfo(
  name = PpssppModelTargetEnvironment.NAME,
  attributes = [TargetAttributeType(type = Void::class)],
  elements = [TargetElementType(type = Void::class)],
)
class PpssppModelTargetEnvironment(
  process: PpssppModelTargetProcess
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetProcess>(
    process.model, process, NAME, NAME
  ),
  TargetEnvironment {

  companion object {
    const val NAME = "Environment"

    const val ARCH = "Allegrex"
    const val DEBUGGER = "PPSSPP"
    const val OS = "default"
    const val ENDIAN = "Little"
  }

  init {
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetEnvironment.ARCH_ATTRIBUTE_NAME to ARCH,
        TargetEnvironment.DEBUGGER_ATTRIBUTE_NAME to DEBUGGER,
        TargetEnvironment.OS_ATTRIBUTE_NAME to OS,
        TargetEnvironment.ENDIAN_ATTRIBUTE_NAME to ENDIAN,
      ),
      UpdateReason.INITIALIZED
    )
  }
}
