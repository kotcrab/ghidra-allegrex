package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.PpssppState

interface PpssppStateListener {
  fun onStateChange(state: PpssppState, paused: Boolean)

  fun stepCompleted()
}
