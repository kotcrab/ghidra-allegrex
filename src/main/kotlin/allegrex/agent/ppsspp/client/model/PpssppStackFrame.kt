package allegrex.agent.ppsspp.client.model

data class PpssppStackFrame(
  val entry: Long,
  val pc: Long,
  val sp: Long,
  val stackSize: Long,
  val code: String
)
