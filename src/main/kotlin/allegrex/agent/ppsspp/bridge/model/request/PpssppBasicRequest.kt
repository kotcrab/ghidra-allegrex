package allegrex.agent.ppsspp.bridge.model.request

import java.util.UUID

data class PpssppBasicRequest(
  override val event: String,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest
