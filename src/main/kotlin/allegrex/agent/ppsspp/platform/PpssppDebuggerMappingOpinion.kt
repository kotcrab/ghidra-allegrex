package allegrex.agent.ppsspp.platform

import ghidra.debug.api.model.DebuggerMappingOffer
import ghidra.debug.api.model.DebuggerMappingOpinion
import ghidra.app.plugin.core.debug.mapping.DefaultDebuggerMappingOffer
import ghidra.dbg.target.TargetEnvironment
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetProcess
import ghidra.program.model.lang.CompilerSpecID
import ghidra.program.model.lang.LanguageID

@Suppress("unused")
class PpssppDebuggerMappingOpinion : DebuggerMappingOpinion {
  companion object {
    private const val PPSSPP = "PPSSPP"
    private const val ALLEGREX = "Allegrex"
    private val LANG_ID_ALLEGREX_DEFAULT = LanguageID("$ALLEGREX:LE:32:default")
    private val COMP_ID_DEFAULT = CompilerSpecID("default")
  }

  private class PpssppAllegrexOffer(target: TargetObject) : DefaultDebuggerMappingOffer(
    target, 100, PPSSPP, LANG_ID_ALLEGREX_DEFAULT, COMP_ID_DEFAULT, emptySet()
  )

  override fun offersForEnv(env: TargetEnvironment, target: TargetObject, includeOverrides: Boolean): Set<DebuggerMappingOffer> {
    return when {
      env.debugger.equals(PPSSPP, ignoreCase = true) && env.architecture.equals(ALLEGREX, ignoreCase = true) -> {
        setOf(PpssppAllegrexOffer(target))
      }
      else -> emptySet()
    }
  }
}
