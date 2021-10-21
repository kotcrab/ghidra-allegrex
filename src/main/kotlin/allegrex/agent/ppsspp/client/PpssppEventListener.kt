package allegrex.agent.ppsspp.client

import allegrex.agent.ppsspp.client.model.PpssppLogMessage
import allegrex.agent.ppsspp.client.model.PpssppState

interface PpssppEventListener {
  fun onStateChange(state: PpssppState, paused: Boolean)

  fun onStepCompleted()

  fun onLog(message: PpssppLogMessage)
}
