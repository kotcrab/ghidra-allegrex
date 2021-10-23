package allegrex.agent.ppsspp.client.model.event

data class PpssppMemoryBreakpointUpdateEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.breakpoint.update"
  }

  override val event: String = EVENT_NAME
}
