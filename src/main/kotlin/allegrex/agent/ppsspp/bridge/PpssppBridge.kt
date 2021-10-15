package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent
import allegrex.agent.ppsspp.bridge.model.request.PpssppRequest

interface PpssppBridge {
  suspend fun start()

  fun addEventListener(listener: PpssppEventListener)

  fun getBrief(): String

  fun close()

  fun isAlive(): Boolean

  suspend fun ping()

  suspend fun sendRequest(request: PpssppRequest)

  suspend fun <T : PpssppEvent> sendRequestAndWait(request: PpssppRequest): T
}
