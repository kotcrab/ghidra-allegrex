package allegrex.agent.ppsspp.bridge.model

data class PpssppHleModuleMeta(
  val name: String,
  val address: Long,
  val size: Long
) : PpssppModelKey
