package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointListEvent
import java.util.UUID

data class PpssppCpuBreakpointListRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuBreakpointListEvent.EVENT_NAME
}
