package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppGameStatusEvent
import java.util.UUID

data class PpssppGameStatusRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppGameStatusEvent.EVENT_NAME
}
