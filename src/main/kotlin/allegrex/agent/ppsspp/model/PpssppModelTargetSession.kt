package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppLogMessage
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.agent.DefaultTargetModelRoot
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
import java.util.concurrent.CompletableFuture

@TargetObjectSchemaInfo(
  name = "Session",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetSession(model: PpssppDebuggerObjectModel, schema: TargetObjectSchema) :
  DefaultTargetModelRoot(model, "Session", schema),
  TargetAggregate, TargetInterpreter, TargetEventScope, TargetFocusScope {

  companion object {
    private const val COMMANDS_UNSUPPORTED_MESSAGE = "Commands are not supported"
  }

  @get:TargetAttributeType(name = PpssppModelTargetProcess.NAME, required = false, fixed = false)
  var process: PpssppModelTargetProcess? = null

  private val session = this

  init {
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to "Session",
        TargetFocusScope.FOCUS_ATTRIBUTE_NAME to this,
        TargetInterpreter.PROMPT_ATTRIBUTE_NAME to "(PPSSPP)",
      ),
      UpdateReason.INITIALIZED
    )
  }

  fun invalidateMemoryAndRegisterCaches() {
    process?.invalidateMemoryAndRegisterCaches()
  }

  override fun getModel(): PpssppDebuggerObjectModel {
    return super.getModel() as PpssppDebuggerObjectModel
  }

  override fun execute(cmd: String) = getModel().modelScope.futureVoid {
    broadcast().consoleOutput(session, TargetConsole.Channel.STDOUT, COMMANDS_UNSUPPORTED_MESSAGE)
  }

  override fun executeCapture(cmd: String): CompletableFuture<String> {
    return CompletableFuture.completedFuture(COMMANDS_UNSUPPORTED_MESSAGE)
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
      UpdateReason.FOCUS_CHANGED
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
      val oldProcess = process
      process = null
      broadcast().event(
        session,
        oldProcess?.threads?.getAnyThreadOrNull(),
        TargetEventScope.TargetEventType.PROCESS_EXITED,
        UpdateReason.PROCESS_EXITED,
        listOf(oldProcess)
      )
      changeAttributes(listOf(PpssppModelTargetProcess.NAME), emptyList(), emptyMap<String, Any>(), UpdateReason.PROCESS_EXITED)
    }
  }

  private fun initializeProcessIfNeededThen(block: suspend () -> Unit) {
    getModel().modelScope.launch {
      if (process == null) {
        process = PpssppModelTargetProcess(session)
        process?.syncInitial()
        changeAttributes(emptyList(), listOf(process), emptyMap<String, Any>(), UpdateReason.PROCESS_CREATED)
        broadcast().event(
          session,
          null,
          TargetEventScope.TargetEventType.PROCESS_CREATED,
          UpdateReason.PROCESS_CREATED,
          listOf(process)
        )
      }
      block()
    }
  }

  fun log(message: PpssppLogMessage) {
    val channel = when {
      message.isError() -> TargetConsole.Channel.STDERR
      else -> TargetConsole.Channel.STDOUT
    }
    broadcast().consoleOutput(this, channel, message.asFormattedMessage())
  }
}
