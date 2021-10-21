package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.bridge.PpssppApi
import allegrex.agent.ppsspp.bridge.PpssppBridge
import allegrex.agent.ppsspp.bridge.PpssppEventListener
import allegrex.agent.ppsspp.bridge.model.PpssppLogMessage
import allegrex.agent.ppsspp.bridge.model.PpssppState
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.DebuggerModelClosedReason
import ghidra.dbg.agent.AbstractDebuggerObjectModel
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.AnnotatedSchemaContext
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.program.model.address.AddressFactory
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.DefaultAddressFactory
import ghidra.program.model.address.GenericAddressSpace
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.future.future
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import org.apache.logging.log4j.LogManager
import java.util.concurrent.CompletableFuture

class PpssppDebuggerObjectModel(private val bridge: PpssppBridge) : AbstractDebuggerObjectModel() {
  companion object {
    private const val SPACE_NAME_RAM = "ram"

    private val SCHEMA_CTX = AnnotatedSchemaContext()
    private val ROOT_SCHEMA: TargetObjectSchema = SCHEMA_CTX.getSchemaForClass(PpssppModelTargetSession::class.java)

    private val logger = LogManager.getLogger(PpssppDebuggerObjectModel::class.java)
  }

  private val space: AddressSpace = GenericAddressSpace(SPACE_NAME_RAM, 32, AddressSpace.TYPE_RAM, 0)
  private val addressFactory: AddressFactory = DefaultAddressFactory(arrayOf(space))

  val session by lazy {
    PpssppModelTargetSession(this, ROOT_SCHEMA)
  }
  private val completedSession by lazy {
    CompletableFuture.completedFuture(session)
  }

  private val exceptionHandler = CoroutineExceptionHandler { _, cause ->
    logger.error("Unhandled error in PpssppDebuggerObjectModel: ${cause.message ?: "unknown"} (see log)", cause)
  }

  @Suppress("EXPERIMENTAL_API_USAGE")
  private val modelThread = newSingleThreadContext("PpssppDebuggerThread")
  val modelScope = CoroutineScope(CoroutineName("PpssppDebugger") + SupervisorJob() + modelThread + exceptionHandler)

  val api = PpssppApi(bridge)

  init {
    bridge.addEventListener(DebuggerPpssppEventListener())
  }

  fun start() = modelScope.future {
    addModelRoot(session)
    bridge.start()
  }

  override fun getRootSchema(): TargetObjectSchema {
    return ROOT_SCHEMA
  }

  override fun getBrief(): String {
    return "PPSSPP@${bridge.getBrief()}"
  }

  override fun getAddressFactory(): AddressFactory {
    return addressFactory
  }

  private fun terminate() {
    listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL)
    session.invalidateSubtree(session, "Debugger is terminating")
    bridge.close()
    modelScope.cancel()
    modelThread.close()
  }

  override fun fetchModelRoot(): CompletableFuture<out TargetObject> {
    return completedSession
  }

  override fun isAlive(): Boolean {
    return bridge.isAlive()
  }

  override fun ping(content: String?) = modelScope.futureVoid {
    bridge.ping()
  }

  override fun close(): CompletableFuture<Void> {
    return runCatching {
      terminate()
      return super.close()
    }.getOrElse {
      CompletableFuture.failedFuture(it)
    }
  }

  inner class DebuggerPpssppEventListener : PpssppEventListener {
    override fun onStateChange(state: PpssppState, paused: Boolean) {
      modelScope.launch {
        logger.info("State transition: $state, paused: $paused")
        when {
          state == PpssppState.EXITED -> {
            terminate()
          }
          state == PpssppState.NO_GAME -> {
            session.changeAccessible(false)
            session.ppssppNoGame()
          }
          paused -> {
            session.changeAccessible(false)
            session.ppssppPaused()
          }
          state == PpssppState.STEPPING -> {
            session.changeAccessible(true)
            session.ppssppStepping()
          }
          state == PpssppState.RUNNING -> {
            session.invalidateMemoryAndRegisterCaches()
            session.changeAccessible(false)
            session.ppssppRunning()
          }
        }
      }
    }

    override fun onStepCompleted() {
      modelScope.launch {
        session.ppssppStepCompleted()
      }
    }

    override fun onLog(message: PpssppLogMessage) {
      modelScope.launch {
        session.log(message)
      }
    }
  }
}
