package allegrex.agent.ppsspp.bridge.model

data class PpssppCpuRegisterMeta(
  val threadId: Int,
  val categoryId: Int,
  val id: Int,
  val name: String,
  val bitLength: Int = 32
) : PpssppModelKey
