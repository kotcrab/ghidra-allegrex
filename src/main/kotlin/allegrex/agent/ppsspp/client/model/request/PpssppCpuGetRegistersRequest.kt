package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuRegistersEvent
import java.util.UUID

data class PpssppCpuGetRegistersRequest(
  val thread: Long,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuRegistersEvent.EVENT_NAME
}
