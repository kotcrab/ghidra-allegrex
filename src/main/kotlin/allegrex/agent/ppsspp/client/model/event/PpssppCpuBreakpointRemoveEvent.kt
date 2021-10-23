package allegrex.agent.ppsspp.client.model.event

data class PpssppCpuBreakpointRemoveEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.breakpoint.remove"
  }

  override val event: String = EVENT_NAME
}
