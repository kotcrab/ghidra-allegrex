package allegrex.agent.ppsspp.client.model.event

data class PpssppMemoryBreakpointAddEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.breakpoint.add"
  }

  override val event: String = EVENT_NAME
}
