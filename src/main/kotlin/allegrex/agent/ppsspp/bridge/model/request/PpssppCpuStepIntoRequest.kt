package allegrex.agent.ppsspp.bridge.model.request

import java.util.UUID

data class PpssppCpuStepIntoRequest(
  val threadInt: Int,
  override val ticket: String = UUID.randomUUID().toString(),
) : PpssppRequest {
  companion object {
    private const val EVENT_NAME = "cpu.stepInto"
  }

  override val event: String = EVENT_NAME
}
