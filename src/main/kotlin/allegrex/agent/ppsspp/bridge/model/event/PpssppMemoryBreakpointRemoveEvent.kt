package allegrex.agent.ppsspp.bridge.model.event

data class PpssppMemoryBreakpointRemoveEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.breakpoint.remove"
  }

  override val event: String = EVENT_NAME
}
