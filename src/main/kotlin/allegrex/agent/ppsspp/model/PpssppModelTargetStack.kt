package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.DebuggerObjectModel
import ghidra.dbg.target.TargetStack
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

@TargetObjectSchemaInfo(
  name = PpssppModelTargetStack.NAME,
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetStack(
  thread: PpssppModelTargetThread,
  private val threadId: Long,
) :
  PpssppTargetObject<PpssppModelTargetStackFrame, PpssppModelTargetThread>(
    thread.model, thread, NAME, NAME
  ),
  TargetStack {

  companion object {
    const val NAME = "Stack"
  }

  private val targetFrames = mutableMapOf<Int, PpssppModelTargetStackFrame>()

  override fun requestElements(refresh: DebuggerObjectModel.RefreshBehavior) = modelScope.futureVoid {
    val frames = api.backtraceThread(threadId)
    val newTargetFrames = frames
      .mapIndexed { level, frame ->
        getTargetFrame(level).apply { updateFrame(frame) }
      }
    setElements(newTargetFrames, UpdateReason.REFRESHED)
  }

  private fun getTargetFrame(level: Int): PpssppModelTargetStackFrame {
    return targetFrames.getOrPut(level) { PpssppModelTargetStackFrame(this, level) }
  }

  fun getFirstStackFrame(): PpssppModelTargetStackFrame? {
    return targetFrames[0]
  }
}
