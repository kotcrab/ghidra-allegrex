package allegrex.agent.ppsspp.client.model

data class PpssppCpuRegisterMeta(
  val threadId: Long,
  val categoryId: Int,
  val id: Int,
  val name: String,
  val bitLength: Int = 32
) : PpssppModelKey
