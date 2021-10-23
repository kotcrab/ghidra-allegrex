package allegrex.agent.ppsspp.client.model.event

data class PpssppSetRegisterEvent(
  val category: Int,
  val register: Int,
  val uintValue: Long,
  val floatValue: String,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.setReg"
  }

  override val event: String = EVENT_NAME
}
