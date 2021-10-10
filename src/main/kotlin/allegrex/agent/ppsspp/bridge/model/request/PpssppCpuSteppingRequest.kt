package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuSteppingEvent
import java.util.UUID

data class PpssppCpuSteppingRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuSteppingEvent.EVENT_NAME
}
