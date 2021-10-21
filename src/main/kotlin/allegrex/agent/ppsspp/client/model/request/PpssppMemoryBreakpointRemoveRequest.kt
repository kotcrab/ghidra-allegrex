package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointRemoveEvent
import java.util.UUID

data class PpssppMemoryBreakpointRemoveRequest(
  val address: Long,
  val size: Long,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryBreakpointRemoveEvent.EVENT_NAME
}
