package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppStackFrame
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetStackFrame
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils

@TargetObjectSchemaInfo(
  name = PpssppModelTargetStackFrame.NAME,
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetStackFrame(
  stack: PpssppModelTargetStack,
  private val level: Int
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetStack>(
    stack.model, stack, PathUtils.makeKey(PathUtils.makeIndex(level)), NAME
  ),
  TargetStackFrame {
  companion object {
    const val NAME = "StackFrame"
  }

  fun updateFrame(frame: PpssppStackFrame) {
    val pcAddr = getModel().addressFactory
      .defaultAddressSpace
      .getAddress(frame.pc.toString(16))

    changeAttributes(
      emptyList(),
      mapOf(
        TargetStackFrame.PC_ATTRIBUTE_NAME to pcAddr,
        TargetStackFrame.DISPLAY_ATTRIBUTE_NAME to "#$level: ${frame.code}",
      ),
      UpdateReason.REFRESHED
    )
  }
}
