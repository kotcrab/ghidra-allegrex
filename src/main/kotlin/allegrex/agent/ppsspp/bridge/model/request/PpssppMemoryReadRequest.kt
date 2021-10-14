package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryReadEvent
import java.util.UUID

data class PpssppMemoryReadRequest(
  val address: Long,
  val size: Long,
  val replacements: Boolean = false,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryReadEvent.EVENT_NAME
}
