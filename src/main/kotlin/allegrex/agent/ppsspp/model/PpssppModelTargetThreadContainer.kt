package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppHleThread
import allegrex.agent.ppsspp.client.model.PpssppHleThreadMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import java.util.concurrent.ConcurrentHashMap

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

  // TODO switch to normal map
  private val threadModels = ConcurrentHashMap<PpssppHleThreadMeta, PpssppModelTargetThread>()

  init {
    requestElements(false)
  }

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    // TODO handle refresh
    val threads = api.listThreads()
      .map { getTargetThread(it) }
    val delta = setElements(threads, "Refreshed")
    delta.removed
      .map { it.value.thread.meta() }
//      .forEach { getModel().deleteModelObject(it) }
  }

  private fun getTargetThread(thread: PpssppHleThread): PpssppModelTargetThread {
    return threadModels.getOrPut(thread.meta()) { PpssppModelTargetThread(this, thread) }
  }

  fun getThreadById(id: Long): PpssppModelTargetThread? {
    return threadModels.values.firstOrNull { it.thread.id == id }
  }

  fun invalidateRegisterCaches() {

  }

  fun updateThreads() {
    requestElements(true)
  }
}
