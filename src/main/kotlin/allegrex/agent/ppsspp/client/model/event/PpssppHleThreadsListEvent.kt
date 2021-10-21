package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppHleThread

data class PpssppHleThreadsListEvent(
  val threads: List<PpssppHleThread>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "hle.thread.list"
  }

  override val event: String = EVENT_NAME
}
