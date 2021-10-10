package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuStatusEvent
import java.util.UUID

data class PpssppCpuStatusRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuStatusEvent.EVENT_NAME
}
