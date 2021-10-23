package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointUpdateEvent
import java.util.UUID

data class PpssppCpuBreakpointUpdateRequest(
  val address: Long,
  val enabled: Boolean,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuBreakpointUpdateEvent.EVENT_NAME
}
