package allegrex.agent.ppsspp.bridge.websocket

import allegrex.agent.ppsspp.bridge.PpssppBridge
import allegrex.agent.ppsspp.bridge.PpssppEventListener
import allegrex.agent.ppsspp.bridge.model.PpssppException
import allegrex.agent.ppsspp.bridge.model.PpssppInstance
import allegrex.agent.ppsspp.bridge.model.PpssppState
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuStatusEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameStatusEvent
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuStatusRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppGameStatusRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppRequest
import com.google.gson.Gson
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.features.json.GsonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.client.features.websocket.DefaultClientWebSocketSession
import io.ktor.client.features.websocket.WebSockets
import io.ktor.client.features.websocket.webSocketSession
import io.ktor.client.request.get
import io.ktor.http.HttpMethod
import io.ktor.http.cio.websocket.Frame
import io.ktor.http.cio.websocket.send
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.apache.logging.log4j.LogManager

class PpssppWsBridge(
  private val connectionUrl: String? = null,
  private val gson: Gson = Gson()
) : PpssppBridge {
  companion object {
    private const val REPORT_PPSSPP_URL = "https://report.ppsspp.org/match/list"
    private const val DEBUGGER_PATH = "/debugger"

    private val logger = LogManager.getLogger(PpssppWsBridge::class.java)
  }

  private val client = HttpClient(CIO) {
    install(JsonFeature) {
      serializer = GsonSerializer()
    }
    install(WebSockets)
  }

  @Suppress("EXPERIMENTAL_API_USAGE")
  private val bridgeThread = newSingleThreadContext("PpssppWsBridgeThread")
  private val bridgeScope = CoroutineScope(CoroutineName("PpssppWsBridge") + SupervisorJob() + bridgeThread)
  private val outgoingChannel = Channel<PpssppRequest>()

  private val eventDispatcher = PpssppWsEventDispatcher(gson)

  override suspend fun start() {
    withContext(bridgeScope.coroutineContext) {
      logger.debug("PPSSPP WebSocket bridge is starting")
      val instances = getPpssppInstances()
      if (instances.isEmpty()) {
        throw PpssppException("Can't find any available PPSSPP instance")
      }

      for (instance in instances) {
        val session = tryConnect(instance)
        if (session != null) {
          launchReceiver(session)
          launchSender(session)
          syncState()
          return@withContext
        }
      }
      throw PpssppException("Can't connect to any PPSSPP instance")
    }
  }

  private suspend fun syncState() {
    val gameStatus = sendRequestAndWait<PpssppGameStatusEvent>(PpssppGameStatusRequest())
    val cpuStatus = sendRequestAndWait<PpssppCpuStatusEvent>(PpssppCpuStatusRequest())
    when {
      gameStatus.game == null -> eventDispatcher.initState(PpssppState.NO_GAME, gameStatus.paused)
      cpuStatus.stepping -> eventDispatcher.initState(PpssppState.STEPPING, gameStatus.paused)
      else -> eventDispatcher.initState(PpssppState.RUNNING, gameStatus.paused)
    }
  }

  private suspend fun getPpssppInstances(): List<PpssppInstance> {
    return when {
      connectionUrl.isNullOrBlank() -> client.get(REPORT_PPSSPP_URL)
      else -> {
        val parts = connectionUrl.split(":", limit = 2)
        val ip = parts[0]
        val port = parts.getOrNull(1)?.toIntOrNull() ?: 80
        listOf(PpssppInstance(ip, port))
      }
    }
  }

  private suspend fun tryConnect(instance: PpssppInstance) = runCatching {
    client.webSocketSession(HttpMethod.Get, instance.ip, instance.port, DEBUGGER_PATH)
  }.getOrNull()

  private suspend fun launchReceiver(session: DefaultClientWebSocketSession) = bridgeScope.launch {
    try {
      for (message in session.incoming) {
        if (message is Frame.Text) {
          val response = String(message.data)
          logger.debug("<<< WS $response")
          eventDispatcher.handleWsMessage(response)
        }
      }
    } finally {
      eventDispatcher.handleWsClose()
    }
  }

  private fun launchSender(session: DefaultClientWebSocketSession) = bridgeScope.launch {
    for (message in outgoingChannel) {
      val request = gson.toJson(message)
      logger.debug(">>> WS $request")
      session.send(request)
    }
  }

  override suspend fun sendRequest(request: PpssppRequest) {
    outgoingChannel.send(request)
  }

  override suspend fun <T : PpssppEvent> sendRequestAndWait(request: PpssppRequest): T {
    val ticket = request.ticket
    if (ticket.isNullOrBlank()) {
      throw PpssppException("Ticket must be provided in the request if you want to wait for a response")
    }
    val channel = withContext(bridgeScope.coroutineContext) {
      eventDispatcher.addWaiter(ticket)
    }
    outgoingChannel.send(request)
    return channel.receiveUnchecked()
  }

  @Suppress("UNCHECKED_CAST")
  private suspend fun <T : PpssppEvent> ReceiveChannel<PpssppEvent>.receiveUnchecked(): T {
    return receive() as T
  }

  override fun addEventListener(listener: PpssppEventListener) {
    runBlocking(bridgeScope.coroutineContext) {
      eventDispatcher.addEventListener(listener)
    }
  }

  override fun getBrief(): String {
    return "WebSocket: ${if (connectionUrl.isNullOrBlank()) "auto" else connectionUrl}"
  }

  override fun close() {
    bridgeScope.cancel()
    bridgeThread.close()
    client.close()
  }

  override fun isAlive(): Boolean {
    return bridgeScope.isActive
  }

  override suspend fun ping() {
    sendRequestAndWait<PpssppGameStatusEvent>(PpssppGameStatusRequest())
  }
}
