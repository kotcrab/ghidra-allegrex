package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppCpuStatus

data class PpssppCpuStatusEvent(
  val stepping: Boolean,
  val paused: Boolean,
  val pc: Long,
  val ticks: Long,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.status"
  }

  override val event: String = EVENT_NAME

  fun toCpuStatus(): PpssppCpuStatus {
    return PpssppCpuStatus(stepping, paused, pc, ticks)
  }
}
