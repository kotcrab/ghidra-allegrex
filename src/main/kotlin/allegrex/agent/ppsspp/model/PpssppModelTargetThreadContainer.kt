package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppHleThread
import allegrex.agent.ppsspp.client.model.PpssppHleThreadMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

// TODO

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

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    // TODO handle refresh
    val threads = api.listThreads()
      .map { getTargetThread(it) }
    val delta = setElements(threads, UpdateReason.REFRESHED)
    delta.removed
      .map { it.value.thread.meta() }
//      .forEach { getModel().deleteModelObject(it) }
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
    // TODO
  }

  fun updateThreads() {
    requestElements(true)
  }
}
