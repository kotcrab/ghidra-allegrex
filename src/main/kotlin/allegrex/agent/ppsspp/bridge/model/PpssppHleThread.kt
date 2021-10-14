package allegrex.agent.ppsspp.bridge.model

data class PpssppHleThread(
  val id: Long,
  val name: String,
  val status: Int,
  val statuses: List<String>,
  val pc: Long,
  val entry: Long,
  val initialStackSize: Long,
  val currentStackSize: Long,
  val priority: Int,
  val waitType: Int,
  val isCurrent: Boolean
) {
  fun meta() = PpssppHleThreadMeta(id)
}
