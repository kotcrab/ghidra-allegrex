package allegrex.agent.ppsspp.bridge.model

data class PpssppMemoryBreakpoint(
  val address: Long,
  val size: Long,
  val enabled: Boolean,
  val log: Boolean,
  val read: Boolean,
  val write: Boolean,
  val change: Boolean,
  val logFormat: String?,
  val symbol: String?
)
