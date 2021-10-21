package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppGame
import allegrex.agent.ppsspp.client.model.PpssppGameStatus

data class PpssppGameStatusEvent(
  val game: PpssppGame?,
  val paused: Boolean,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "game.status"
  }

  override val event: String = EVENT_NAME

  fun toGameStatus(): PpssppGameStatus {
    return PpssppGameStatus(game, paused)
  }
}
