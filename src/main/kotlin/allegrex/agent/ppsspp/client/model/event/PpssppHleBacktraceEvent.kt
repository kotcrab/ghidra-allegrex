package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppStackFrame

data class PpssppHleBacktraceEvent(
  val frames: List<PpssppStackFrame>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "hle.backtrace"
  }

  override val event: String = EVENT_NAME
}
