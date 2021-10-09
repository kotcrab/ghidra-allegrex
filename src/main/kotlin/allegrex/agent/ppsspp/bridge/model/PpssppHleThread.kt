package allegrex.agent.ppsspp.bridge.model

data class PpssppHleThread(
  val id: Int,
  val name: String,
  val status: Int,
  val statuses: List<String>,
  val pc: Int,
  val entry: Int,
  val initialStackSize: Int,
  val currentStackSize: Int,
  val priority: Int,
  val waitType: Int,
  val isCurrent: Boolean
) {
  val meta by lazy {
    PpssppHleThreadMeta(id)
  }
}
