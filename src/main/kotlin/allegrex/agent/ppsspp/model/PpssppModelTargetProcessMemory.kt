package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.bridge.model.PpssppMemoryRange
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.error.DebuggerMemoryAccessException
import ghidra.dbg.target.TargetMemory
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetObjectSchema
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRangeImpl
import kotlinx.coroutines.future.future
import java.util.concurrent.ConcurrentHashMap

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

  // TODO investigate, normal map may be enough
  private val ranges = ConcurrentHashMap<PpssppMemoryRange, PpssppModelTargetMemoryRegion>()

  init {
    requestElements(false)
  }

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val ranges = api.getMemoryMap()
      .map { getTargetMemoryRange(it) }
    setElements(ranges, "Refreshed") // delta.removed ignored, we can assume memory ranges will never change
  }

  private fun getTargetMemoryRange(range: PpssppMemoryRange): PpssppModelTargetMemoryRegion {
    return ranges.getOrPut(range) { PpssppModelTargetMemoryRegion(this, range) }
  }

  override fun readMemory(address: Address, length: Int) = modelScope.future {
    val memory = this@PpssppModelTargetProcessMemory
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
    val memory = this@PpssppModelTargetProcessMemory
    api.writeMemory(address.offset, data)
    listeners.fire.memoryUpdated(memory, address, data)
  }

  fun invalidateMemoryCaches() {
    listeners.fire.invalidateCacheRequested(this)
  }
}
