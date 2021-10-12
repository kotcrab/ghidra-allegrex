package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppStackFrame

data class PpssppHleBacktraceEvent(
  val frames: List<PpssppStackFrame>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "hle.backtrace"
  }

  override val event: String = EVENT_NAME
}
