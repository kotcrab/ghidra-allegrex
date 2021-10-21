package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuSteppingEvent
import java.util.UUID

data class PpssppCpuSteppingRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuSteppingEvent.EVENT_NAME
}
