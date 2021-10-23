package allegrex.agent.ppsspp.client.model.event

data class PpssppCpuEvaluateEvent(
  val uintValue: Long,
  val floatValue: String,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.evaluate"
  }

  override val event: String = EVENT_NAME
}
