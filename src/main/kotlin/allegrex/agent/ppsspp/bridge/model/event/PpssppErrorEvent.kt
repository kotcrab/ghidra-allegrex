package allegrex.agent.ppsspp.bridge.model.event

data class PpssppErrorEvent(
  val message: String,
  val level: Int,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "error"
  }

  override val event: String = EVENT_NAME
}
