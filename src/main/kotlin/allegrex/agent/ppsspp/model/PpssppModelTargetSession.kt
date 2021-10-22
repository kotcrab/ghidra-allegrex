package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppLogMessage
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.agent.DefaultTargetModelRoot
import ghidra.dbg.target.TargetAccessConditioned
import ghidra.dbg.target.TargetAggregate
import ghidra.dbg.target.TargetConsole
import ghidra.dbg.target.TargetEventScope
import ghidra.dbg.target.TargetFocusScope
import ghidra.dbg.target.TargetInterpreter
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.CompletableFuture

@TargetObjectSchemaInfo(
  name = "Session",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetSession(model: PpssppDebuggerObjectModel, schema: TargetObjectSchema) :
  DefaultTargetModelRoot(model, "Session", schema),
  TargetAccessConditioned, TargetAggregate, TargetInterpreter, TargetEventScope, TargetFocusScope {

  @get:TargetAttributeType(name = PpssppModelTargetProcess.NAME, required = false, fixed = false)
  var process: PpssppModelTargetProcess? = null
  val processLock = Mutex()

  private val session = this

  init {
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to "Session",
        TargetFocusScope.FOCUS_ATTRIBUTE_NAME to this,
        TargetInterpreter.PROMPT_ATTRIBUTE_NAME to "(PPSSPP)",
        TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME to true
      ),
      "Initialized"
    )
  }

  fun invalidateMemoryAndRegisterCaches() {

  }

  fun changeAccessible(accessible: Boolean) {
// TODO this doesn't work as expected (prevents model updates)

//    changeAttributes(
//      listOf(),
//      mapOf(
//        TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME to accessible
//      ),
//      "Accessibility changed"
//    )
  }

  override fun getModel(): PpssppDebuggerObjectModel {
    return super.getModel() as PpssppDebuggerObjectModel
  }

  override fun execute(cmd: String) = getModel().modelScope.futureVoid {
    listeners.fire.consoleOutput(session, TargetConsole.Channel.STDOUT, "Commands are not supported")
  }

  override fun executeCapture(cmd: String): CompletableFuture<String> {
    return CompletableFuture.completedFuture("Commands are not supported")
  }

  override fun requestFocus(focus: TargetObject?) = getModel().modelScope.futureVoid {
    if (focus !is PpssppModelTargetThread) {
      return@futureVoid
    }
    changeFocus(focus)
  }

  fun changeFocus(focus: TargetObject?) {
    if (focus == null) {
      return
    }
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetFocusScope.FOCUS_ATTRIBUTE_NAME to focus
      ),
      "Focus changed"
    )
  }

  fun ppssppStepping() {
    initializeProcessIfNeededThen {
      process?.changeState(running = false)
    }
  }

  fun ppssppRunning() {
    initializeProcessIfNeededThen {
      process?.changeState(running = true)
    }
  }

  fun ppssppPaused() {
    initializeProcessIfNeededThen {
      process?.changeState(running = false)
    }
  }

  fun ppssppStepCompleted() {
    initializeProcessIfNeededThen {
      process?.stepCompleted()
    }
  }

  fun ppssppNoGame() {
    getModel().modelScope.launch {
      processLock.withLock {
        val oldProcess = process
        process = null
        resync(true, true) // TODO doesn't work
        listeners.fire.event(session, null, TargetEventScope.TargetEventType.PROCESS_EXITED, "Process exited", listOf(oldProcess))
      }
    }
  }

  private fun initializeProcessIfNeededThen(block: suspend () -> Unit) {
    getModel().modelScope.launch {
      processLock.withLock {
        if (process == null) {
          process = PpssppModelTargetProcess(session)
          process?.syncInitial()
          changeAttributes(emptyList(), listOf(process), emptyMap<String, Any>(), "Process created")
          listeners.fire.event(session, null, TargetEventScope.TargetEventType.PROCESS_CREATED, "Process created", listOf(process))
        }
      }
      block()
    }
  }

  fun log(message: PpssppLogMessage) {
    val channel = when {
      message.isError() -> TargetConsole.Channel.STDERR
      else -> TargetConsole.Channel.STDOUT
    }
    listeners.fire.consoleOutput(this, channel, message.asFormattedMessage())
  }
}
