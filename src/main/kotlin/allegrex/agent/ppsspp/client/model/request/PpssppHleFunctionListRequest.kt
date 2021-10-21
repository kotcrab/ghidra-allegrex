package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppHleFunctionListEvent
import java.util.UUID

data class PpssppHleFunctionListRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppHleFunctionListEvent.EVENT_NAME
}
