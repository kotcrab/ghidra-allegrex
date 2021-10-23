package allegrex.agent.ppsspp.client

import allegrex.agent.ppsspp.client.model.event.PpssppEvent
import allegrex.agent.ppsspp.client.model.request.PpssppRequest

interface PpssppClient {
  suspend fun start()

  fun addEventListener(listener: PpssppEventListener)

  fun getBrief(): String

  fun close()

  fun isAlive(): Boolean

  suspend fun ping()

  suspend fun sendRequest(request: PpssppRequest)

  suspend fun <T : PpssppEvent> sendRequestAndWait(request: PpssppRequest): T
}
