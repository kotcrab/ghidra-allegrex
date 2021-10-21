package allegrex.agent.ppsspp.model

import ghidra.async.AsyncUtils
import ghidra.dbg.target.TargetBreakpointLocation
import ghidra.dbg.target.TargetBreakpointSpec
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import java.util.concurrent.CompletableFuture

// TODO

@TargetObjectSchemaInfo(
  name = "Breakpoint",
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetBreakpoint(
  breakpoints: PpssppModelTargetBreakpointContainer,
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetBreakpointContainer>(
    breakpoints.model, breakpoints, NAME, "Breakpoint"
  ), TargetBreakpointLocation, TargetBreakpointSpec {
  companion object {
    const val NAME = "Breakpoint"
  }

  override fun disable(): CompletableFuture<Void> {
    return AsyncUtils.NIL
  }

  override fun enable(): CompletableFuture<Void> {
    return AsyncUtils.NIL
  }

  override fun addAction(action: TargetBreakpointSpec.TargetBreakpointAction?) {
  }

  override fun removeAction(action: TargetBreakpointSpec.TargetBreakpointAction?) {
  }
}
