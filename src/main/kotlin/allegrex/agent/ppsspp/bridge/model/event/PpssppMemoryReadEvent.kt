package allegrex.agent.ppsspp.bridge.model.event

data class PpssppMemoryReadEvent(
  val base64: String,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.read"
  }

  override val event: String = EVENT_NAME
}
