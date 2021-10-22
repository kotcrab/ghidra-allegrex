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

  private val functions = mutableMapOf<PpssppHleFunction, PpssppModelTargetSymbol>()

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val types = api.listFunctions()
      .map { getTargetSymbol(it) } // TODO update in case of PPSSPP changed
    setElements(types, "Refreshed")
  }

  private fun getTargetSymbol(function: PpssppHleFunction): PpssppModelTargetSymbol {
    return functions.getOrPut(function) { PpssppModelTargetSymbol(this, function) }
  }
}
