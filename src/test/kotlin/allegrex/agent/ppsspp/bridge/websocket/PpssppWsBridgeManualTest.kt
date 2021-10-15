package allegrex.agent.ppsspp.bridge.websocket

import allegrex.agent.ppsspp.bridge.PpssppApi
import allegrex.agent.ppsspp.bridge.PpssppEventListener
import allegrex.agent.ppsspp.bridge.model.PpssppLogMessage
import allegrex.agent.ppsspp.bridge.model.PpssppState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.apache.logging.log4j.LogManager

fun main() {
  val logger = LogManager.getLogger("main")
  val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  val bridge = PpssppWsBridge()
  val api = PpssppApi(bridge)

  bridge.addEventListener(
    object : PpssppEventListener {
      override fun onStateChange(state: PpssppState, paused: Boolean) {
        logger.info("PPSSPP state change: $state, paused: $paused")
      }

      override fun onStepCompleted() {
        logger.info("PPSSPP step completed")
      }

      override fun onLog(message: PpssppLogMessage) {
        logger.debug("PPSSPP: ${message.asFormattedMessage().trim()}")
      }
    }
  )

  scope.launch {
    logger.info("Starting bridge")
    bridge.start()

    println(api.cpuStatus())
  }

  Thread.sleep(120L * 1000)
  logger.info("Closing bridge")
  bridge.close()
  scope.cancel()
}
