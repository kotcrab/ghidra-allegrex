package allegrex.agent.ppsspp.client.model.request

import java.util.UUID

data class PpssppCpuStepOutRequest(
  val thread: Long,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  companion object {
    private const val EVENT_NAME = "cpu.stepOut"
  }

  override val event: String = EVENT_NAME
}
