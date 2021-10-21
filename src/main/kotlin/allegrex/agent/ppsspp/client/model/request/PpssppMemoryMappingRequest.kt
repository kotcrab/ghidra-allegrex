package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppMemoryMappingEvent
import java.util.UUID

data class PpssppMemoryMappingRequest(
  val replacements: Boolean = false,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryMappingEvent.EVENT_NAME
}
