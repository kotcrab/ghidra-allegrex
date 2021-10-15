package allegrex.agent.ppsspp.bridge.model.request

import allegrex.agent.ppsspp.bridge.model.event.PpssppHleModuleListEvent
import java.util.UUID

data class PpssppHleModuleListRequest(
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  override val event: String = PpssppHleModuleListEvent.EVENT_NAME
}
