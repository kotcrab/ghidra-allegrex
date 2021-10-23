package allegrex.agent.ppsspp.client.model.request

import java.util.UUID

data class PpssppCpuStepOverRequest(
  val thread: Long,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  companion object {
    private const val EVENT_NAME = "cpu.stepOver"
  }

  override val event: String = EVENT_NAME
}
