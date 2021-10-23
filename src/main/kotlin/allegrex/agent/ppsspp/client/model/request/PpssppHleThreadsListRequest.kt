package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppHleThreadsListEvent
import java.util.UUID

data class PpssppHleThreadsListRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppHleThreadsListEvent.EVENT_NAME
}
