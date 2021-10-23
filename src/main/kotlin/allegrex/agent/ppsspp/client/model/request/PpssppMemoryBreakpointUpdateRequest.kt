package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointUpdateEvent
import java.util.UUID

data class PpssppMemoryBreakpointUpdateRequest(
  val address: Long,
  val size: Long,
  val enabled: Boolean,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryBreakpointUpdateEvent.EVENT_NAME
}
