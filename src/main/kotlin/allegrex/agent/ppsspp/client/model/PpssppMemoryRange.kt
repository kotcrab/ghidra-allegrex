package allegrex.agent.ppsspp.client.model

data class PpssppMemoryRange(
  val type: String,
  val subtype: String,
  val name: String,
  val address: Long,
  val size: Long
) : PpssppModelKey
