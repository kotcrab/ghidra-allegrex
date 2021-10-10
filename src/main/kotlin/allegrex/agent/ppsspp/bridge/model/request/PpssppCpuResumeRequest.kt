package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuResumeEvent
import java.util.UUID

data class PpssppCpuResumeRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuResumeEvent.EVENT_NAME
}
