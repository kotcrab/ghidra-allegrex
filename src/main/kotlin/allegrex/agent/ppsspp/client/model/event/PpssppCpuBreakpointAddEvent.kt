package allegrex.agent.ppsspp.client.model.event

data class PpssppCpuBreakpointAddEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.breakpoint.add"
  }

  override val event: String = EVENT_NAME
}
