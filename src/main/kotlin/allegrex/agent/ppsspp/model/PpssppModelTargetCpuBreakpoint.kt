package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppCpuBreakpoint
import allegrex.agent.ppsspp.client.model.PpssppCpuBreakpointMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetBreakpointLocation
import ghidra.dbg.target.TargetBreakpointSpec
import ghidra.dbg.target.TargetBreakpointSpecContainer
import ghidra.dbg.target.TargetDeletable
import ghidra.dbg.target.TargetObject
import ghidra.dbg.target.TargetTogglable
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.dbg.util.PathUtils
import ghidra.program.model.address.Address
import kotlinx.coroutines.future.await

@TargetObjectSchemaInfo(
  name = "CpuBreakpoint",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetCpuBreakpoint(
  private val breakpoints: PpssppModelTargetBreakpointContainer,
  private val meta: PpssppCpuBreakpointMeta
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetBreakpointContainer>(
    breakpoints.model, breakpoints, PathUtils.makeKey("cpu-${meta.address}"), "BreakpointSpec"
  ), TargetBreakpointLocation, TargetBreakpointSpec, TargetDeletable, TargetTogglable {
  companion object {
    const val NAME = "Breakpoint"
  }

  private val actions = mutableListOf<TargetBreakpointSpec.TargetBreakpointAction>()

  init {
    val address: Address = getModel().addressFactory
      .defaultAddressSpace
      .getAddress(meta.address.toString(16))

    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetBreakpointSpec.CONTAINER_ATTRIBUTE_NAME to breakpoints,
        TargetBreakpointSpec.EXPRESSION_ATTRIBUTE_NAME to meta.address.toString(),
        TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME to TargetBreakpointSpecContainer.TargetBreakpointKindSet.of(
          TargetBreakpointSpec.TargetBreakpointKind.HW_EXECUTE
        ),
        TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME to address,
        TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME to 1,
        TargetBreakpointLocation.SPEC_ATTRIBUTE_NAME to this,
      ),
      UpdateReason.INITIALIZED
    )
  }

  fun updateFromActual(breakpoint: PpssppCpuBreakpoint) {
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetTogglable.ENABLED_ATTRIBUTE_NAME to breakpoint.enabled
      ),
      UpdateReason.REFRESHED
    )
  }

  override fun delete() = modelScope.futureVoid {
    api.removeCpuBreakpoint(meta.address)
    breakpoints.resync().await()
  }

  override fun disable() = modelScope.futureVoid {
    api.updateCpuBreakpoint(meta.address, enabled = false)
    changeAttributes(emptyList(), emptyList(), mapOf(TargetTogglable.ENABLED_ATTRIBUTE_NAME to false), UpdateReason.ENABLED_STATE_CHANGED)
  }

  override fun enable() = modelScope.futureVoid {
    api.updateCpuBreakpoint(meta.address, enabled = true)
    changeAttributes(emptyList(), emptyList(), mapOf(TargetTogglable.ENABLED_ATTRIBUTE_NAME to true), UpdateReason.ENABLED_STATE_CHANGED)
  }

  override fun addAction(action: TargetBreakpointSpec.TargetBreakpointAction) {
    synchronized(actions) {
      actions.add(action)
    }
  }

  override fun removeAction(action: TargetBreakpointSpec.TargetBreakpointAction) {
    synchronized(actions) {
      actions.remove(action)
    }
  }
}
