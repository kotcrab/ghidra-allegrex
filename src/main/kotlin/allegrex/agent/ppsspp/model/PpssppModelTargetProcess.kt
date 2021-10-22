package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetAggregate
import ghidra.dbg.target.TargetEventScope
import ghidra.dbg.target.TargetExecutionStateful
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState
import ghidra.dbg.target.TargetInterruptible
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetProcess
import ghidra.dbg.target.TargetResumable
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import kotlinx.coroutines.future.await
import org.apache.logging.log4j.LogManager

@TargetObjectSchemaInfo(
  name = PpssppModelTargetProcess.NAME,
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetProcess(
  session: PpssppModelTargetSession,
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetSession>(
    session.model, session, NAME, "Process"
  ),
  TargetAggregate, TargetExecutionStateful, TargetResumable, TargetInterruptible, TargetProcess { // TargetSteppable

  companion object {
    const val NAME = "Process"

    private val logger = LogManager.getLogger(PpssppModelTargetProcess::class.java)
  }

  @get:TargetAttributeType(name = PpssppModelTargetEnvironment.NAME, required = true, fixed = true)
  val environment = PpssppModelTargetEnvironment(this)

  @get:TargetAttributeType(name = PpssppModelTargetModuleContainer.NAME, required = true, fixed = true)
  val modules = PpssppModelTargetModuleContainer(this)

  @get:TargetAttributeType(name = PpssppModelTargetProcessMemory.NAME, required = true, fixed = true)
  val memory = PpssppModelTargetProcessMemory(this)

  @get:TargetAttributeType(name = PpssppModelTargetSymbolContainer.NAME, required = true, fixed = true)
  val symbols = PpssppModelTargetSymbolContainer(this)

  @get:TargetAttributeType(name = PpssppModelTargetThreadContainer.NAME, required = true, fixed = true)
  val threads = PpssppModelTargetThreadContainer(this)

  @get:TargetAttributeType(name = PpssppModelTargetBreakpointContainer.NAME, required = true, fixed = true)
  val breakpoints = PpssppModelTargetBreakpointContainer(this)

  init {
    changeAttributes(
      emptyList(),
      listOf(environment, modules, memory, symbols, threads, breakpoints),
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to "Process",
        TargetExecutionStateful.STATE_ATTRIBUTE_NAME to TargetExecutionState.STOPPED, // this will be set to the actual state by the first state event
      ),
      UpdateReason.INITIALIZED
    )
  }

  suspend fun syncInitial() {
    listOf(modules, memory, threads, breakpoints)
      .map { it.resync().await() }
  }

  override fun resume() = modelScope.futureVoid {
    api.resume()
  }

  override fun interrupt() = modelScope.futureVoid {
    api.stepping()
  }

  suspend fun changeState(running: Boolean) {
    val executionState = when (running) {
      true -> TargetExecutionState.RUNNING
      else -> TargetExecutionState.STOPPED
    }
    changeAttributes(
      emptyList(),
      mapOf(
        TargetExecutionStateful.STATE_ATTRIBUTE_NAME to executionState,
      ),
      "Execution state change"
    )

    threads.updateThreads()
    val currentThread = api.listThreads().firstOrNull { it.isCurrent }
    if (currentThread == null) {
      logger.warn("Entered stepping state but current thread does not exist")
    }
    val threadTarget = if (currentThread != null) threads.getThreadById(currentThread.id) else null
    when (running) {
      true -> {
        session.listeners.fire.event(
          session, threadTarget, TargetEventScope.TargetEventType.RUNNING, UpdateReason.RUNNING, listOfNotNull(threadTarget)
        )
        invalidateMemoryAndRegisterCaches()
      }
      false -> {
        threadTarget?.let {
          session.changeFocus(it.getFirstStackFrame())
          it.updateThread()
        }
        session.listeners.fire.event(
          session, threadTarget, TargetEventScope.TargetEventType.STOPPED, UpdateReason.STOPPED, listOfNotNull(threadTarget)
        )
      }
    }
  }

  suspend fun stepCompleted() {
    val currentThread = api.listThreads().firstOrNull { it.isCurrent }
    if (currentThread == null) {
      logger.warn("Can't complete step when current thread is null")
      return
    }
    val threadTarget = threads.getThreadById(currentThread.id)
    threadTarget?.let {
      session.changeFocus(it.getFirstStackFrame())
      it.updateThread()
    }
//    threads.updateThreads()
    session.listeners.fire.event(
      session, threadTarget, TargetEventScope.TargetEventType.STEP_COMPLETED, UpdateReason.STEP_COMPLETED, listOf(threadTarget)
    )
  }

  fun invalidateMemoryAndRegisterCaches() {
    memory.invalidateMemoryCaches()
    threads.invalidateRegisterCaches()
  }
}
