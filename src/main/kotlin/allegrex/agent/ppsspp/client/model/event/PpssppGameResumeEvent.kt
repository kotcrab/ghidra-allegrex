package allegrex.agent.ppsspp.client.model.event

import allegrex.agent.ppsspp.client.model.PpssppGame

data class PpssppGameResumeEvent(
  val game: PpssppGame?,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "game.resume"
  }

  override val event: String = EVENT_NAME
}
