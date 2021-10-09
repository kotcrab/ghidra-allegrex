package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuRegistersEvent
import java.util.UUID

data class PpssppCpuGetRegistersRequest(
  val threadId: Int,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuRegistersEvent.EVENT_NAME
}
