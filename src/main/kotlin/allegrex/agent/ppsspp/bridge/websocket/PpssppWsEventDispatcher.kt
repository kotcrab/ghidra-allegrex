package allegrex.agent.ppsspp.bridge.websocket

import allegrex.agent.ppsspp.bridge.PpssppEventListener
import allegrex.agent.ppsspp.bridge.model.PpssppException
import allegrex.agent.ppsspp.bridge.model.PpssppLogMessage
import allegrex.agent.ppsspp.bridge.model.PpssppState
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuResumeEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuSteppingEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppErrorEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGamePauseEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameQuitEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameResumeEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameStartEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppLogEvent
import allegrex.agent.ppsspp.bridge.model.event.ppssppEventMap
import com.google.gson.Gson
import com.google.gson.JsonObject
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.SendChannel
import org.apache.logging.log4j.LogManager

class PpssppWsEventDispatcher(
  private val gson: Gson
) {
  companion object {
    private val logger = LogManager.getLogger(PpssppWsEventDispatcher::class.java)
    private val ignoredEvents = setOf("input.analog", "input.buttons")
  }

  private val listeners = mutableListOf<PpssppEventListener>()
  private val waiters = mutableMapOf<String, SendChannel<PpssppEvent>>()

  private var ppssppState = PpssppState.NO_GAME
  private var ppssppPaused = false

  fun initState(initialState: PpssppState, initialPaused: Boolean) {
    ppssppState = initialState
    ppssppPaused = initialPaused
    fireStateChange()
  }

  suspend fun handleWsMessage(data: String) {
    val jsonTree = gson.fromJson(data, JsonObject::class.java)
    val eventName = jsonTree["event"].asString
    if (eventName in ignoredEvents) {
      return
    }
    val type = ppssppEventMap[eventName]
    if (type == null) {
      logger.warn("Unhandled event: $data")
      return
    }
    handleEvent(gson.fromJson(jsonTree, type))
  }

  fun handleWsClose() {
    ppssppState = PpssppState.EXITED
    fireStateChange()
  }

  private suspend fun handleEvent(event: PpssppEvent) {
    handleStateEvent(event)
    handleLogEvent(event)
    notifyWaiters(event)
  }

  private fun handleStateEvent(event: PpssppEvent) {
    val previousPpssppState = ppssppState
    val previousPpssppPaused = ppssppPaused
    when (event) {
      is PpssppCpuResumeEvent -> ppssppState = PpssppState.RUNNING
      is PpssppCpuSteppingEvent -> ppssppState = PpssppState.STEPPING
      is PpssppGamePauseEvent -> ppssppPaused = true
      is PpssppGameQuitEvent -> {
        ppssppState = PpssppState.NO_GAME
        ppssppPaused = false
      }
      is PpssppGameResumeEvent -> ppssppPaused = false
      is PpssppGameStartEvent -> {
        ppssppState = PpssppState.RUNNING
        ppssppPaused = false
      }
    }
    when {
      previousPpssppState != ppssppState || previousPpssppPaused != ppssppPaused -> fireStateChange()
      event is PpssppCpuSteppingEvent -> fireStepCompleted()
    }
  }

  private fun handleLogEvent(event: PpssppEvent) {
    if (event !is PpssppLogEvent) {
      return
    }
    fireLog(event.toLogMessage())
  }

  private suspend fun notifyWaiters(event: PpssppEvent) {
    if (event.ticket == null) {
      return
    }
    val handler = waiters.remove(event.ticket)
      ?: return
    when (event) {
      is PpssppErrorEvent -> handler.close(PpssppException(event.message))
      else -> handler.send(event)
    }
  }

  fun addWaiter(ticket: String): ReceiveChannel<PpssppEvent> {
    val channel: Channel<PpssppEvent> = Channel()
    waiters[ticket] = channel
    return channel
  }

  fun addEventListener(listener: PpssppEventListener) {
    listeners.add(listener)
  }

  private fun fireStateChange() = fireEvent {
    it.onStateChange(ppssppState, ppssppPaused)
  }

  private fun fireStepCompleted() = fireEvent {
    it.onStepCompleted()
  }

  private fun fireLog(message: PpssppLogMessage) = fireEvent {
    it.onLog(message)
  }

  private fun fireEvent(handler: (PpssppEventListener) -> Unit) {
    runCatching {
      listeners.forEach {
        handler(it)
      }
    }.onFailure { cause ->
      logger.error("Unhandled error in event listener: ${cause.message ?: "unknown"}", cause)
    }
  }
}
