package allegrex.agent.ppsspp.platform

import ghidra.app.plugin.core.debug.mapping.AbstractDebuggerTargetTraceMapper
import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper
import ghidra.app.plugin.core.debug.mapping.DefaultDebuggerMemoryMapper
import ghidra.app.plugin.core.debug.mapping.DefaultDebuggerRegisterMapper
import ghidra.dbg.target.TargetMemory
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetRegisterContainer
import ghidra.program.model.lang.CompilerSpecID
import ghidra.program.model.lang.LanguageID

class PpssppTargetTraceMapper(
  target: TargetObject,
  langID: LanguageID,
  csId: CompilerSpecID,
  extraRegNames: Collection<String>
) : AbstractDebuggerTargetTraceMapper(target, langID, csId, extraRegNames) {
  override fun createMemoryMapper(memory: TargetMemory): DebuggerMemoryMapper {
    return DefaultDebuggerMemoryMapper(language, memory.model)
  }

  override fun createRegisterMapper(registers: TargetRegisterContainer): DebuggerRegisterMapper {
    return DefaultDebuggerRegisterMapper(cSpec, registers, false)
  }
}
