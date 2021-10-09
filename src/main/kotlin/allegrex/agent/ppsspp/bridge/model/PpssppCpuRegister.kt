package allegrex.agent.ppsspp.bridge.model

data class PpssppCpuRegister(
  val threadId: Int,
  val categoryId: Int,
  val id: Int,
  val name: String,
  val uintValue: Long,
  val floatValue: String,
  val bitLength: Int = 32,
) {
  val meta by lazy {
    PpssppCpuRegisterMeta(threadId, categoryId, id, name, bitLength)
  }
}
