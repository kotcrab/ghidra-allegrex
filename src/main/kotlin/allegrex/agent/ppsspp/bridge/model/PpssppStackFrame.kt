package allegrex.agent.ppsspp.bridge.model

data class PpssppStackFrame(
  val entry: Int,
  val pc: Int,
  val sp: Int,
  val stackSize: Int,
  val code: String
)
