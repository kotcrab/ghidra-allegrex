package allegrex.agent.ppsspp.bridge.model

data class PpssppCpuBreakpoint(
  val address: Long,
  val enabled: Boolean,
  val log: Boolean,
  val condition: String?,
  val logFormat: String?,
  val symbol: String?,
  val code: String
)
