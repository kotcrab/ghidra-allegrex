package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppHleBacktraceEvent
import java.util.UUID

data class PpssppHleBacktraceRequest(
  val thread: Long,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppHleBacktraceEvent.EVENT_NAME
}
