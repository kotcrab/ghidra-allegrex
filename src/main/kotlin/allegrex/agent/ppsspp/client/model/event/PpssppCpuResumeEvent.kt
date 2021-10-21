package allegrex.agent.ppsspp.client.model.event

data class PpssppCpuResumeEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.resume"
  }

  override val event: String = EVENT_NAME
}
