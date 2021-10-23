package allegrex.agent.ppsspp.client.model

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
) {
  fun meta() = PpssppMemoryBreakpointMeta(address, size)
}
