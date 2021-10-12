package allegrex.agent.ppsspp.bridge.model

data class PpssppMemoryRange(
  val type: String,
  val subtype: String,
  val name: String,
  val address: Long,
  val size: Long
) : PpssppModelKey
