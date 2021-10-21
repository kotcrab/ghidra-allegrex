package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointAddEvent
import java.util.UUID

data class PpssppCpuBreakpointAddRequest(
  val address: Long,
  val enabled: Boolean,
  val log: Boolean,
  val condition: String?,
  val logFormat: String?,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppCpuBreakpointAddEvent.EVENT_NAME
}
