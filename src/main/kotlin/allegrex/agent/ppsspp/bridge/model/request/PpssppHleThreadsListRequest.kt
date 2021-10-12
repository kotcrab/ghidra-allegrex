package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppHleBacktraceEvent
import java.util.UUID

data class PpssppHleThreadsListRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppHleBacktraceEvent.EVENT_NAME
}
