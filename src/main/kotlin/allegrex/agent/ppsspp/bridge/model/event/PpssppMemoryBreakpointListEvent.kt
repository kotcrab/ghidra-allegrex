package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppMemoryBreakpoint

data class PpssppMemoryBreakpointListEvent(
  val breakpoints: List<PpssppMemoryBreakpoint>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.breakpoint.list"
  }

  override val event: String = EVENT_NAME
}
