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
  TargetAggregate, TargetExecutionStateful, TargetResumable, TargetInterruptible, TargetProcess {

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
      listOf(environment, memory, modules, symbols, threads, breakpoints),
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to "Process",
        TargetExecutionStateful.STATE_ATTRIBUTE_NAME to TargetExecutionState.STOPPED, // this will be set to the actual state by the first state event
      ),
      UpdateReason.INITIALIZED
    )
  }

  suspend fun syncInitial() {
    listOf(memory, modules, threads, breakpoints)
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
      UpdateReason.EXECUTION_STATE_CHANGED
    )

    val remoteThreads = api.listThreads()
    threads.updateUsingThreads(remoteThreads)
    val currentThread = remoteThreads.firstOrNull { it.isCurrent }
    if (currentThread == null) {
      logger.warn("Entered stepping state but current thread does not exist")
    }
    val threadTarget = if (currentThread != null) threads.getThreadById(currentThread.id) else null
    when (running) {
      true -> {
        session.broadcast().event(
          session, threadTarget, TargetEventScope.TargetEventType.RUNNING, UpdateReason.RUNNING, listOfNotNull(threadTarget)
        )
        invalidateMemoryAndRegisterCaches()
      }
      false -> {
        updateAfterThreadStop(threadTarget, TargetEventScope.TargetEventType.STOPPED, UpdateReason.STOPPED)
      }
    }
  }

  suspend fun stepCompleted() {
    val remoteThreads = api.listThreads()
    val currentThread = remoteThreads.firstOrNull { it.isCurrent }
    if (currentThread == null) {
      logger.warn("Can't complete step when current thread is not set")
      return
    }
    threads.updateUsingThreads(remoteThreads)
    val threadTarget = threads.getThreadById(currentThread.id)
    updateAfterThreadStop(threadTarget, TargetEventScope.TargetEventType.STEP_COMPLETED, UpdateReason.STEP_COMPLETED)
  }

  private suspend fun updateAfterThreadStop(threadTarget: PpssppModelTargetThread?, type: TargetEventScope.TargetEventType, reason: String) {
    threadTarget?.let {
      it.updateThread()
      session.changeFocus(it.getFirstStackFrame())
    }
    session.broadcast().event(session, threadTarget, type, reason, listOf(threadTarget))
  }

  fun invalidateMemoryAndRegisterCaches() {
    memory.invalidateMemoryCaches()
    threads.invalidateRegisterCaches()
  }
}
