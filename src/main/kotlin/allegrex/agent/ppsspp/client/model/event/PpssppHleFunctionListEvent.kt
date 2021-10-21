package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppHleFunction

data class PpssppHleFunctionListEvent(
  val functions: List<PpssppHleFunction>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "hle.func.list"
  }

  override val event: String = EVENT_NAME
}
