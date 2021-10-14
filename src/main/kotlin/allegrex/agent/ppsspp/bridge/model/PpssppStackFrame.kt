package allegrex.agent.ppsspp.bridge.model

data class PpssppStackFrame(
  val entry: Long,
  val pc: Long,
  val sp: Long,
  val stackSize: Long,
  val code: String
)
