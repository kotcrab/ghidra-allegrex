package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppMemoryRange

data class PpssppMemoryMappingEvent(
  val ranges: List<PpssppMemoryRange>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.mapping"
  }

  override val event: String = EVENT_NAME
}
