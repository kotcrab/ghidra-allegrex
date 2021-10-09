package allegrex.agent.ppsspp.bridge.model.event

data class PpssppCpuSteppingEvent(
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.stepping"
  }

  override val event: String = EVENT_NAME
}
