package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppHleThread

data class PpssppHleThreadsEvent(
  val threads: List<PpssppHleThread>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "hle.thread.list"
  }

  override val event: String = EVENT_NAME
}
