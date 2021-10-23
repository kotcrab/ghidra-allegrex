package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppCpuBreakpoint
import allegrex.agent.ppsspp.client.model.PpssppCpuBreakpointMeta
import allegrex.agent.ppsspp.client.model.PpssppMemoryBreakpoint
import allegrex.agent.ppsspp.client.model.PpssppMemoryBreakpointMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetBreakpointLocationContainer
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind
import ghidra.dbg.target.TargetBreakpointSpecContainer
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.program.model.address.AddressRange
import kotlinx.coroutines.future.await

@TargetObjectSchemaInfo(
  name = "BreakpointContainer",
  elements = [TargetElementType(type = PpssppModelTargetCpuBreakpoint::class), TargetElementType(type = PpssppModelTargetMemoryBreakpoint::class)],
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetBreakpointContainer(
  process: PpssppModelTargetProcess,
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetProcess>(
    process.model, process, NAME, "BreakpointContainer"
  ), TargetBreakpointSpecContainer, TargetBreakpointLocationContainer {
  companion object {
    const val NAME = "Breakpoints"

    private val SUPPORTED_KINDS = TargetBreakpointSpecContainer.TargetBreakpointKindSet.of(
      TargetBreakpointKind.READ,
      TargetBreakpointKind.WRITE,
      TargetBreakpointKind.HW_EXECUTE,
    )
  }

  private val targetCpuBreakpoints = mutableMapOf<PpssppCpuBreakpointMeta, PpssppModelTargetCpuBreakpoint>()
  private val targetMemoryBreakpoints = mutableMapOf<PpssppMemoryBreakpointMeta, PpssppModelTargetMemoryBreakpoint>()

  init {
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetBreakpointSpecContainer.SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME to SUPPORTED_KINDS,
      ),
      UpdateReason.INITIALIZED
    )
  }

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val newTargetCpuBreakpoints = api.listCpuBreakpoints()
      .map { getTargetCpuBreakpoint(it) }
    val newTargetMemoryBreakpoints = api.listMemoryBreakpoints()
      .map { getTargetMemoryBreakpoint(it) }
    val delta = setElements(newTargetCpuBreakpoints + newTargetMemoryBreakpoints, UpdateReason.REFRESHED)
    if (!delta.isEmpty) {
      targetCpuBreakpoints.entries
        .removeIf { delta.removed.containsValue(it.value) }
      targetMemoryBreakpoints.entries
        .removeIf { delta.removed.containsValue(it.value) }
    }
  }

  private fun getTargetCpuBreakpoint(breakpoint: PpssppCpuBreakpoint): PpssppModelTargetCpuBreakpoint {
    val meta = breakpoint.meta()
    return targetCpuBreakpoints.getOrPut(meta) { PpssppModelTargetCpuBreakpoint(this, meta) }
      .apply { updateFromActual(breakpoint) }
  }

  private fun getTargetMemoryBreakpoint(breakpoint: PpssppMemoryBreakpoint): PpssppModelTargetMemoryBreakpoint {
    val meta = breakpoint.meta()
    return targetMemoryBreakpoints.getOrPut(meta) { PpssppModelTargetMemoryBreakpoint(this, meta) }
      .apply { updateFromActual(breakpoint) }
  }

  override fun placeBreakpoint(expression: String, kinds: Set<TargetBreakpointKind>) = modelScope.futureVoid {
    placeBreakpoint(api.evaluate(expression).uintValue, 4, kinds)
  }

  override fun placeBreakpoint(range: AddressRange, kinds: Set<TargetBreakpointKind>) = modelScope.futureVoid {
    placeBreakpoint(range.minAddress.offset, range.length, kinds)
  }

  private suspend fun placeBreakpoint(minAddress: Long, length: Long, kinds: Set<TargetBreakpointKind>) {
    val wantsCpu = kinds.contains(TargetBreakpointKind.HW_EXECUTE)
    val wantsMemory = kinds.contains(TargetBreakpointKind.READ) || kinds.contains(TargetBreakpointKind.WRITE)
    if (wantsCpu && length == 1L) {
      api.addCpuBreakpoint(minAddress)
    }
    if (wantsMemory) {
      api.addMemoryBreakpoint(
        minAddress, length,
        read = kinds.contains(TargetBreakpointKind.READ),
        write = kinds.contains(TargetBreakpointKind.WRITE),
        change = false // TODO no way to represent this for now
      )
    }
    resync().await()
  }
}
