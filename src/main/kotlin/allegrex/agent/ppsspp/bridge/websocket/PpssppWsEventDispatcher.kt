package allegrex.agent.ppsspp.bridge.websocket

import allegrex.agent.ppsspp.bridge.PpssppStateListener
import allegrex.agent.ppsspp.bridge.model.PpssppState
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuResumeEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuSteppingEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGamePauseEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameQuitEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameResumeEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameStartEvent
import allegrex.agent.ppsspp.bridge.model.event.ppssppEventMap
import com.google.gson.Gson
import com.google.gson.JsonObject
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.channels.SendChannel
import org.apache.logging.log4j.LogManager
import java.util.concurrent.ConcurrentHashMap

class PpssppWsEventDispatcher(
  private val gson: Gson
) {
  companion object {
    private val logger = LogManager.getLogger(PpssppWsEventDispatcher::class.java)
    private val ignoredEvents = setOf("input.analog", "input.buttons", "log") // TODO might be nice to handle "log" event somehow
  }

  private val listeners = mutableListOf<PpssppStateListener>() // TODO maybe one persistent listener is enough and we can skip synchronized?
  private val waiters = ConcurrentHashMap<String, SendChannel<PpssppEvent>>()

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
    if (previousPpssppState != ppssppState || previousPpssppPaused != ppssppPaused) {
      fireStateChange()
    } else if (event is PpssppCpuSteppingEvent) {
      fireStepCompleted()
    }
    if (event.ticket != null) {
      notifyWaiters(event)
    }
  }

  private suspend fun notifyWaiters(event: PpssppEvent) {
    waiters.remove(event.ticket)
      ?.send(event)
  }

  fun addWaiter(ticket: String): ReceiveChannel<PpssppEvent> {
    val channel: Channel<PpssppEvent> = Channel()
    waiters[ticket] = channel
    return channel
  }

  fun addStateListener(listener: PpssppStateListener) {
    synchronized(listeners) {
      listeners.add(listener)
    }
  }

  private fun fireStateChange() {
    synchronized(listeners) {
      listeners.forEach {
        it.onStateChange(ppssppState, ppssppPaused)
      }
    }
  }

  private fun fireStepCompleted() {
    synchronized(listeners) {
      listeners.forEach {
        it.stepCompleted()
      }
    }
  }
}
