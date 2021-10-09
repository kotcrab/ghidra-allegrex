package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.request.PpssppRequest
import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent

interface PpssppBridge {
  suspend fun start()

  fun addStateListener(listener: PpssppStateListener)

  fun getBrief(): String

  fun close()

  fun isAlive(): Boolean

  suspend fun ping()

  suspend fun sendRequest(request: PpssppRequest)

  suspend fun <T : PpssppEvent> sendRequestAndWait(request: PpssppRequest): T
}
