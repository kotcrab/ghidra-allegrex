package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppLogMessage

data class PpssppLogEvent(
  val timestamp: String,
  val header: String,
  val message: String,
  val level: Int,
  val channel: String,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "log"
  }

  override val event: String = EVENT_NAME

  fun toLogMessage(): PpssppLogMessage {
    return PpssppLogMessage(timestamp, header, message, level, channel)
  }
}
