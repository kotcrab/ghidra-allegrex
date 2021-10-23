package allegrex.agent.ppsspp.client.model.event

data class PpssppCpuBreakpointUpdateEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.breakpoint.update"
  }

  override val event: String = EVENT_NAME
}
