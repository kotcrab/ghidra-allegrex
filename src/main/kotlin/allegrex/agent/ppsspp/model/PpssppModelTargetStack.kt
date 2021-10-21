package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetStack
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

// TODO

@TargetObjectSchemaInfo(
  name = "Stack",
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true
)
class PpssppModelTargetStack(
  thread: PpssppModelTargetThread,
) :
  PpssppTargetObject<PpssppModelTargetStackFrame, PpssppModelTargetThread>(
    thread.model, thread, NAME, "Stack"
  ),
  TargetStack {
  companion object {
    const val NAME = "Stack"
  }

  private val frames = mutableListOf(PpssppModelTargetStackFrame(this, 0, thread.thread.pc))

  init {
//    requestElements(false)
    setElements(frames, "Initialized")
  }

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    // TODO handle refresh properly
  }

  fun remakeFrame(pc: Long) {
    synchronized(frames) {
      frames.clear()
      frames.add(PpssppModelTargetStackFrame(this, 0, pc))
      setElements(frames, "Initialized")
    }
  }

  fun getFirstStackFrame(): PpssppModelTargetStackFrame {
    return frames.first()
  }
}
