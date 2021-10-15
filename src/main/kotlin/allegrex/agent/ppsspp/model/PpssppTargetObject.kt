package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.bridge.PpssppApi
import ghidra.dbg.agent.DefaultTargetObject
import ghidra.dbg.target.TargetObject
import kotlinx.coroutines.CoroutineScope

abstract class PpssppTargetObject<E : TargetObject, P : TargetObject>(
  private val ppssppModel: PpssppDebuggerObjectModel, parent: P, key: String, typeHint: String
) : DefaultTargetObject<E, P>(ppssppModel, parent, key, typeHint) {
  val modelScope: CoroutineScope
    get() = ppssppModel.modelScope

  val api: PpssppApi
    get() = ppssppModel.api

  val session: PpssppModelTargetSession
    get() = ppssppModel.session

  override fun getModel(): PpssppDebuggerObjectModel {
    return ppssppModel
  }
}
