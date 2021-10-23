package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppGame

data class PpssppGameQuitEvent(
  val game: PpssppGame?,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "game.quit"
  }

  override val event: String = EVENT_NAME
}
