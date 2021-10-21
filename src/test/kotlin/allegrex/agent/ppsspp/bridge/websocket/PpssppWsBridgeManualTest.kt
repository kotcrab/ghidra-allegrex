package allegrex.agent.ppsspp.bridge.websocket

import allegrex.agent.ppsspp.bridge.PpssppApi
import allegrex.agent.ppsspp.bridge.PpssppEventListener
import allegrex.agent.ppsspp.bridge.model.PpssppLogMessage
import allegrex.agent.ppsspp.bridge.model.PpssppState
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.LogManager

fun main() {
  val logger = LogManager.getLogger("main")
  val exceptionHandler = CoroutineExceptionHandler { _, cause ->
    logger.error("Unhandled error: ${cause.message ?: "unknown"}", cause)
  }
  @Suppress("EXPERIMENTAL_API_USAGE") val thread = newSingleThreadContext("TestThread")
  val scope = CoroutineScope(SupervisorJob() + thread + exceptionHandler)
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

  runBlocking(scope.coroutineContext) {
    logger.info("Starting bridge")
    bridge.start()

    api.stepping()
    val threads = api.listThreads().first { it.name == "user_main" }
    api.backtraceThread(threads.id)

    logger.info(api.cpuStatus())
  }

  logger.info("Closing bridge")
  bridge.close()
  scope.cancel()
  thread.close()
}
