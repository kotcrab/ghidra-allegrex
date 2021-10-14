package allegrex.agent.ppsspp.bridge.model

data class PpssppCpuStatus(
  val stepping: Boolean,
  val paused: Boolean,
  val pc: Long,
  val ticks: Long,
)
