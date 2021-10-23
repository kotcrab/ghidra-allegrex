package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppHleFunction
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetSymbolNamespace
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo

@TargetObjectSchemaInfo(
  name = "SymbolContainer",
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetSymbolContainer(
  process: PpssppModelTargetProcess,
) :
  PpssppTargetObject<PpssppModelTargetSymbol, PpssppModelTargetProcess>(
    process.model, process, NAME, "SymbolContainer"
  ),
  TargetSymbolNamespace {

  companion object {
    const val NAME = "Symbols"
  }

  private val targetSymbols = mutableMapOf<PpssppHleFunction, PpssppModelTargetSymbol>()

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val newTargetSymbols = api.listFunctions()
      .map { getTargetSymbol(it) }
    val delta = setElements(newTargetSymbols, UpdateReason.REFRESHED)
    if (!delta.isEmpty) {
      targetSymbols.entries
        .removeIf { delta.removed.containsValue(it.value) }
    }
  }

  private fun getTargetSymbol(function: PpssppHleFunction): PpssppModelTargetSymbol {
    return targetSymbols.getOrPut(function) { PpssppModelTargetSymbol(this, function) }
  }
}
