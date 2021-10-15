package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.PpssppLogMessage
import allegrex.agent.ppsspp.bridge.model.PpssppState

interface PpssppEventListener {
  fun onStateChange(state: PpssppState, paused: Boolean)

  fun onStepCompleted()

  fun onLog(message: PpssppLogMessage)
}
