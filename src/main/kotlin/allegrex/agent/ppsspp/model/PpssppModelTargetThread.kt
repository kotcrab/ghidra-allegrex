package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppException
import allegrex.agent.ppsspp.client.model.PpssppHleThread
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetSteppable
import ghidra.dbg.target.TargetThread
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils

// TODO

@TargetObjectSchemaInfo(
  name = "Thread",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetThread(
  threads: PpssppModelTargetThreadContainer,
  val thread: PpssppHleThread
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetThreadContainer>(
    threads.model, threads, PathUtils.makeKey(PathUtils.makeIndex(thread.id)), "Thread"
  ),
  TargetThread,
  TargetSteppable {

  companion object {
    private val SUPPORTED_KINDS = TargetSteppable.TargetStepKindSet.of(
      TargetSteppable.TargetStepKind.FINISH,
      TargetSteppable.TargetStepKind.INTO,
      TargetSteppable.TargetStepKind.OVER,
      TargetSteppable.TargetStepKind.EXTENDED
    )
  }

  @get:TargetAttributeType(name = PpssppModelTargetRegisterContainerAndBank.REGISTERS_NAME, required = true, fixed = true)
  val gprRegisters = PpssppModelTargetRegisterContainerAndBank(this, thread.id)

  @get:TargetAttributeType(name = PpssppModelTargetStack.NAME, required = true, fixed = true)
  val stack = PpssppModelTargetStack(this)

  init {
    changeAttributes(
      emptyList(),
      listOf(gprRegisters, stack), // FIXME stack refresh
      mapOf(
        TargetObject.DISPLAY_ATTRIBUTE_NAME to "${thread.name} (${thread.id})",
        TargetSteppable.SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME to SUPPORTED_KINDS, // FIXME
      ),
      UpdateReason.INITIALIZED
    )
  }

  override fun step(kind: TargetSteppable.TargetStepKind) = modelScope.futureVoid {
    when (kind) {
      TargetSteppable.TargetStepKind.FINISH -> api.stepOut(thread.id)
      TargetSteppable.TargetStepKind.INTO -> api.stepInto(thread.id)
      TargetSteppable.TargetStepKind.OVER -> api.stepOver(thread.id)
      // TODO this seems to be always enabled in UI regardless of SUPPORTED_KINDS so let's just step out
      TargetSteppable.TargetStepKind.EXTENDED -> api.stepOut(thread.id)
      else -> throw PpssppException("Unsupported step kind: $kind")
    }
  }

  fun getFirstStackFrame(): PpssppModelTargetStackFrame {
    return stack.getFirstStackFrame()
  }

  suspend fun updateThread() { // TODO
    val pc = api.listThreads().firstOrNull { it.id == thread.id }?.pc ?: 0
    stack.remakeFrame(pc)
  }
}
