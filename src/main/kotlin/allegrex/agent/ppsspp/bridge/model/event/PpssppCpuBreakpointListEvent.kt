package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppCpuBreakpoint

data class PpssppCpuBreakpointListEvent(
  val breakpoints: List<PpssppCpuBreakpoint>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.breakpoint.list"
  }

  override val event: String = EVENT_NAME
}
