package allegrex.agent.ppsspp.client.model.event

data class PpssppMemoryWriteEvent(
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "memory.write"
  }

  override val event: String = EVENT_NAME
}
