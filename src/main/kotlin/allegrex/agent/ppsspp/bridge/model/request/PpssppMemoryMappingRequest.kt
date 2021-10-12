package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryMappingEvent
import java.util.UUID

data class PpssppMemoryMappingRequest(
  val replacements: Boolean = false,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryMappingEvent.EVENT_NAME
}
