package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppGame

data class PpssppGamePauseEvent(
  val game: PpssppGame?,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "game.pause"
  }

  override val event: String = EVENT_NAME
}
