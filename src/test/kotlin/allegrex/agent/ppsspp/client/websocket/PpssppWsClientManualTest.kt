package allegrex.agent.ppsspp.client.websocket

import allegrex.agent.ppsspp.client.PpssppApi
import allegrex.agent.ppsspp.client.PpssppEventListener
import allegrex.agent.ppsspp.client.model.PpssppLogMessage
import allegrex.agent.ppsspp.client.model.PpssppState
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.LogManager

@OptIn(DelicateCoroutinesApi::class)
fun main() {
  val logger = LogManager.getLogger("main")
  val exceptionHandler = CoroutineExceptionHandler { _, cause ->
    logger.error("Unhandled error: ${cause.message ?: "unknown"}", cause)
  }
  val thread = newSingleThreadContext("TestThread")
  val scope = CoroutineScope(SupervisorJob() + thread + exceptionHandler)
  val client = PpssppWsClient()
  val api = PpssppApi(client)

  client.addEventListener(
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
    logger.info("Starting client")
    client.start()

    api.stepping()
    val threads = api.listThreads().first { it.name == "user_main" }
    api.backtraceThread(threads.id)

    logger.info(api.cpuStatus())
  }

  logger.info("Closing client")
  client.close()
  scope.cancel()
  thread.close()
}
