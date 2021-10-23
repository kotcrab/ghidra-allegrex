package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointListEvent
import java.util.UUID

data class PpssppMemoryBreakpointListRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryBreakpointListEvent.EVENT_NAME
}
