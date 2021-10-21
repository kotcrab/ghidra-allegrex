package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointAddEvent
import java.util.UUID

data class PpssppMemoryBreakpointAddRequest(
  val address: Long,
  val size: Long,
  val enabled: Boolean,
  val log: Boolean,
  val read: Boolean,
  val write: Boolean,
  val change: Boolean,
  val logFormat: String?,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppMemoryBreakpointAddEvent.EVENT_NAME
}
