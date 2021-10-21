package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppHleModule

data class PpssppHleModuleListEvent(
  val modules: List<PpssppHleModule>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "hle.module.list"
  }

  override val event: String = EVENT_NAME
}
