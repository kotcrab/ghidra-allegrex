package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppGame

data class PpssppGameResumeEvent(
  val game: PpssppGame?,
  override val ticket: String?,
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "game.resume"
  }

  override val event: String = EVENT_NAME
}
