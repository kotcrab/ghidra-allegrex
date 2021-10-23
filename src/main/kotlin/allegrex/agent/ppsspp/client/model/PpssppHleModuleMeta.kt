package allegrex.agent.ppsspp.client.model

data class PpssppHleModuleMeta(
  val name: String,
  val address: Long,
  val size: Long
) : PpssppModelKey
