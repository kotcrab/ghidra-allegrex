package allegrex.agent.ppsspp.client.model.request

import allegrex.agent.ppsspp.client.model.event.PpssppSetRegisterEvent
import java.util.UUID

data class PpssppSetRegisterRequest(
  val thread: Long,
  val category: Int,
  val register: Int,
  val value: String,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppSetRegisterEvent.EVENT_NAME
}
