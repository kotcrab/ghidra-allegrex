package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppMemoryRange
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.error.DebuggerMemoryAccessException
import ghidra.dbg.target.TargetMemory
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRangeImpl
import kotlinx.coroutines.future.await
import kotlinx.coroutines.future.future
import kotlinx.coroutines.runBlocking

@TargetObjectSchemaInfo(
  name = PpssppModelTargetProcessMemory.NAME,
  attributes = [TargetAttributeType(type = Void::class)],
  canonicalContainer = true,
  elementResync = TargetObjectSchema.ResyncMode.ONCE
)
class PpssppModelTargetProcessMemory(
  process: PpssppModelTargetProcess
) :
  PpssppTargetObject<PpssppModelTargetMemoryRegion, PpssppModelTargetProcess>(
    process.model, process, NAME, "ProcessMemory"
  ),
  TargetMemory {

  companion object {
    const val NAME = "Memory"
  }

  private val memoryRegions = mutableMapOf<PpssppMemoryRange, PpssppModelTargetMemoryRegion>()
  private val memory = this

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val ranges = api.getMemoryMap()
      .map { getTargetMemoryRegion(it) }
    val delta = setElements(ranges, UpdateReason.REFRESHED)
    if (!delta.isEmpty) {
      memoryRegions.entries
        .removeIf { delta.removed.containsValue(it.value) }
    }
  }

  private fun getTargetMemoryRegion(range: PpssppMemoryRange): PpssppModelTargetMemoryRegion {
    return memoryRegions.getOrPut(range) { PpssppModelTargetMemoryRegion(this, range) }
  }

  override fun readMemory(address: Address, length: Int) = modelScope.future {
    val range = AddressRangeImpl(address, length.toLong())
    try {
      val bytes = api.readMemory(address.offset, length.toLong())
      listeners.fire.memoryUpdated(memory, address, bytes)
      return@future bytes
    } catch (e: Exception) {
      listeners.fire.memoryReadError(memory, range, DebuggerMemoryAccessException("Can't read memory!", e))
      throw e
    }
  }

  override fun writeMemory(address: Address, data: ByteArray) = modelScope.futureVoid {
    api.writeMemory(address.offset, data)
    listeners.fire.memoryUpdated(memory, address, data)
  }

  fun invalidateMemoryCaches() {
    listeners.fire.invalidateCacheRequested(this)
  }
}
