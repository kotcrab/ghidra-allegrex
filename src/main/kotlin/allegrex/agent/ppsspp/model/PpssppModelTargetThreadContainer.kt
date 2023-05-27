package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppHleThread
import allegrex.agent.ppsspp.client.model.PpssppHleThreadMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.DebuggerObjectModel
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

@TargetObjectSchemaInfo(
  name = "ThreadContainer",
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetThreadContainer(
  process: PpssppModelTargetProcess,
) :
  PpssppTargetObject<PpssppModelTargetThread, PpssppModelTargetProcess>(
    process.model, process, NAME, "ThreadContainer"
  ) {
  companion object {
    const val NAME = "Threads"
  }

  private val targetThreads = mutableMapOf<PpssppHleThreadMeta, PpssppModelTargetThread>()

  override fun requestElements(refresh: DebuggerObjectModel.RefreshBehavior) = modelScope.futureVoid {
    updateUsingThreads(api.listThreads())
  }

  fun updateUsingThreads(threads: List<PpssppHleThread>) {
    val newTargetThreads = threads
      .map { getTargetThread(it) }
    val delta = setElements(newTargetThreads, UpdateReason.REFRESHED)
    if (!delta.isEmpty) {
      targetThreads.entries
        .removeIf { delta.removed.containsValue(it.value) }
    }
  }

  private fun getTargetThread(thread: PpssppHleThread): PpssppModelTargetThread {
    return targetThreads.getOrPut(thread.meta()) { PpssppModelTargetThread(this, thread) }
  }

  fun getAnyThreadOrNull(): PpssppModelTargetThread? {
    return targetThreads.values.firstOrNull()
  }

  fun getThreadById(id: Long): PpssppModelTargetThread? {
    return targetThreads.values.firstOrNull { it.thread.id == id }
  }

  fun invalidateRegisterCaches() {
    targetThreads.forEach { (_, thread) ->
      thread.invalidateRegisterCaches()
    }
  }
}
