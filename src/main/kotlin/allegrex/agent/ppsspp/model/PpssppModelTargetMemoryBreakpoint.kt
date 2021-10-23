package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppMemoryBreakpoint
import allegrex.agent.ppsspp.client.model.PpssppMemoryBreakpointMeta
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
  name = "MemoryBreakpoint",
  elements = [TargetElementType(type = Void::class)],
  attributes = [TargetAttributeType(type = Void::class)]
)
class PpssppModelTargetMemoryBreakpoint(
  private val breakpoints: PpssppModelTargetBreakpointContainer,
  private val meta: PpssppMemoryBreakpointMeta
) :
  PpssppTargetObject<TargetObject, PpssppModelTargetBreakpointContainer>(
    breakpoints.model, breakpoints, PathUtils.makeKey("memory-${meta.address}-${meta.size}"), "BreakpointSpec"
  ), TargetBreakpointLocation, TargetBreakpointSpec, TargetDeletable, TargetTogglable {
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
        TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME to address,
        TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME to meta.size.toInt(),
        TargetBreakpointLocation.SPEC_ATTRIBUTE_NAME to this,
      ),
      UpdateReason.INITIALIZED
    )
  }

  fun updateFromActual(breakpoint: PpssppMemoryBreakpoint) {
    val readKind = TargetBreakpointSpec.TargetBreakpointKind.READ
    val writeKind = TargetBreakpointSpec.TargetBreakpointKind.WRITE
    val kinds = when {
      breakpoint.read && breakpoint.write -> arrayOf(readKind, writeKind)
      breakpoint.read -> arrayOf(readKind)
      breakpoint.write -> arrayOf(writeKind)
      else -> emptyArray()
    }
    changeAttributes(
      emptyList(),
      emptyList(),
      mapOf(
        TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME to TargetBreakpointSpecContainer.TargetBreakpointKindSet.of(*kinds),
        TargetTogglable.ENABLED_ATTRIBUTE_NAME to breakpoint.enabled
      ),
      UpdateReason.REFRESHED
    )
  }

  override fun delete() = modelScope.futureVoid {
    api.removeMemoryBreakpoint(meta.address, meta.size)
    breakpoints.resync().await()
  }

  override fun disable() = modelScope.futureVoid {
    changeEnabledState(false)
  }

  override fun enable() = modelScope.futureVoid {
    changeEnabledState(true)
  }

  private suspend fun changeEnabledState(enabled: Boolean) {
    api.updateMemoryBreakpoint(meta.address, meta.size, enabled)
    changeAttributes(emptyList(), emptyList(), mapOf(TargetTogglable.ENABLED_ATTRIBUTE_NAME to enabled), UpdateReason.ENABLED_STATE_CHANGED)
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
