package allegrex.agent.ppsspp.model

import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetStackFrame
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils

// TODO

@TargetObjectSchemaInfo(
  name = "StackFrame",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetStackFrame(
  stack: PpssppModelTargetStack,
  val level: Long,
  val pc: Long
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetStack>(
    stack.model, stack, PathUtils.makeKey(PathUtils.makeIndex(level)), "StackFrame"
  ),
  TargetStackFrame {

  init {
    val pcAddr = getModel().addressFactory
      .defaultAddressSpace
      .getAddress(pc.toString(16))
    changeAttributes(
      emptyList(),
      mapOf(
        TargetStackFrame.PC_ATTRIBUTE_NAME to pcAddr,
        // TODO use comment to show disassembly
      ),
      UpdateReason.INITIALIZED
    )
  }
}
