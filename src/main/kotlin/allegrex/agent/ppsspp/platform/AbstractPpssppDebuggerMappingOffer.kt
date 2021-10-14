package allegrex.agent.ppsspp.platform

import ghidra.app.plugin.core.debug.mapping.AbstractDebuggerMappingOffer
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper
import ghidra.dbg.target.TargetObject
import ghidra.program.model.lang.CompilerSpecID
import ghidra.program.model.lang.LanguageID

abstract class AbstractPpssppDebuggerMappingOffer(
  target: TargetObject, confidence: Int,
  description: String, langID: LanguageID, csID: CompilerSpecID,
  extraRegNames: Collection<String>
) : AbstractDebuggerMappingOffer(target, confidence, description, langID, csID, extraRegNames) {
  override fun take(): DebuggerTargetTraceMapper {
    return PpssppTargetTraceMapper(target, langID, csID, extraRegNames)
  }
}
