package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryWriteEvent
import java.util.UUID

data class PpssppMemoryWriteRequest(
  val address: Long,
  val base64: String,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryWriteEvent.EVENT_NAME
}
