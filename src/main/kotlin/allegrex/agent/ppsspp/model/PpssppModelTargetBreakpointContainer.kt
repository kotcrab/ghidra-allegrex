package allegrex.agent.ppsspp.model

import ghidra.async.AsyncUtils
import ghidra.dbg.target.TargetBreakpointSpec
import ghidra.dbg.target.TargetBreakpointSpecContainer
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.program.model.address.AddressRange
import java.util.concurrent.CompletableFuture

// TODO

@TargetObjectSchemaInfo(
  name = "BreakpointContainer",
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetBreakpointContainer(
  process: PpssppModelTargetProcess,
) :
  PpssppTargetObject<PpssppModelTargetBreakpoint, PpssppModelTargetProcess>(
    process.model, process, NAME, "BreakpointContainer"
  ), TargetBreakpointSpecContainer {
  companion object {
    const val NAME = "Breakpoints"

    private val SUPPORTED_KINDS = TargetBreakpointSpecContainer.TargetBreakpointKindSet.of(
      TargetBreakpointSpec.TargetBreakpointKind.READ,
      TargetBreakpointSpec.TargetBreakpointKind.WRITE,
      TargetBreakpointSpec.TargetBreakpointKind.HW_EXECUTE,
    )
  }

  init {
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
//        TargetObject.DISPLAY_ATTRIBUTE_NAME to "",
        TargetBreakpointSpecContainer.SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME to SUPPORTED_KINDS, // FIXME
      ),
      UpdateReason.INITIALIZED
    )
  }

  override fun placeBreakpoint(expression: String?, kinds: MutableSet<TargetBreakpointSpec.TargetBreakpointKind>?): CompletableFuture<Void> {
    return AsyncUtils.NIL
  }

  override fun placeBreakpoint(range: AddressRange?, kinds: MutableSet<TargetBreakpointSpec.TargetBreakpointKind>?): CompletableFuture<Void> {
    return AsyncUtils.NIL
  }
}
