package allegrex.agent.ppsspp.bridge.model

data class PpssppCpuRegister(
  val threadId: Long,
  val categoryId: Int,
  val id: Int,
  val name: String,
  val uintValue: Long,
  val floatValue: String,
  val bitLength: Int = 32,
) {
  fun meta() = PpssppCpuRegisterMeta(threadId, categoryId, id, name, bitLength)
}
