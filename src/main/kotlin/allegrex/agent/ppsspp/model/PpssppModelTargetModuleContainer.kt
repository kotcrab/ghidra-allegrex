package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppHleModule
import allegrex.agent.ppsspp.client.model.PpssppHleModuleMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetModuleContainer
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

@TargetObjectSchemaInfo(
  name = "ModuleContainer",
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetModuleContainer(
  process: PpssppModelTargetProcess,
) :
  PpssppTargetObject<PpssppModelTargetModule, PpssppModelTargetProcess>(
    process.model, process, NAME, "ModuleContainer"
  ),
  TargetModuleContainer {

  companion object {
    const val NAME = "Modules"
  }

  private val targetModules = mutableMapOf<PpssppHleModuleMeta, PpssppModelTargetModule>()

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val modules = api.listModules()
      .map { getTargetModule(it) }
    val delta = setElements(modules, UpdateReason.REFRESHED)
    if (!delta.isEmpty) {
      targetModules.entries
        .removeIf { delta.removed.containsValue(it.value) }
    }
  }

  private fun getTargetModule(module: PpssppHleModule): PpssppModelTargetModule {
    return targetModules.getOrPut(module.meta()) { PpssppModelTargetModule(this, module) }
  }
}
