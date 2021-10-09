package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.PpssppState

fun interface PpssppStateListener {
  fun onStateChange(newState: PpssppState)
}
