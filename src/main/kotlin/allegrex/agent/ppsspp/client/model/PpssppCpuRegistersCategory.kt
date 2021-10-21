package allegrex.agent.ppsspp.client.model

data class PpssppCpuRegistersCategory(
  val id: Int,
  val name: String,
  val registerNames: List<String>,
  val uintValues: List<Long>,
  val floatValues: List<String>
) {
  fun getRegisters(associateWithThreadId: Long): List<PpssppCpuRegister> {
    return registerNames.mapIndexed { index, name ->
      PpssppCpuRegister(associateWithThreadId, id, index, name, uintValues[index], floatValues[index])
    }
  }
}
