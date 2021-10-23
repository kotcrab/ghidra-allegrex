package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuEvaluateEvent
import java.util.UUID

data class PpssppCpuEvaluateRequest(
  val expression: String,
  val thread: Long? = null,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuEvaluateEvent.EVENT_NAME
}
