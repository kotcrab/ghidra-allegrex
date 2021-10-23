package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppGame

data class PpssppGameStartEvent(
  val game: PpssppGame?,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "game.start"
  }

  override val event: String = EVENT_NAME
}
