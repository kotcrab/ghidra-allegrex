package allegrex.agent.ppsspp.bridge.model.request

import java.util.UUID

data class PpssppCpuStepOutRequest(
  val thread: Int,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  companion object {
    private const val EVENT_NAME = "cpu.stepOut"
  }

  override val event: String = EVENT_NAME
}
