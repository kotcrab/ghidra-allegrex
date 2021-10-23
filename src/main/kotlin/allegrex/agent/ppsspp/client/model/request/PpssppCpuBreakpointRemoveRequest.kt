package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointRemoveEvent
import java.util.UUID

data class PpssppCpuBreakpointRemoveRequest(
  val address: Long,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuBreakpointRemoveEvent.EVENT_NAME
}
