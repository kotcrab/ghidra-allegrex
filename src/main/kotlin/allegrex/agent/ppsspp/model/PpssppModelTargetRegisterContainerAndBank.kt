package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppCpuRegisterMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetRegisterBank
import ghidra.dbg.target.TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME
import ghidra.dbg.target.TargetRegisterContainer
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import kotlinx.coroutines.future.future
import org.apache.logging.log4j.LogManager
import java.math.BigInteger
import java.nio.ByteBuffer

@TargetObjectSchemaInfo(
  name = "RegisterContainer",
  elements = [TargetElementType(type = PpssppModelTargetRegister::class)],
  elementResync = ResyncMode.ONCE,
  attributes = [
    TargetAttributeType(
      name = DESCRIPTIONS_ATTRIBUTE_NAME,
      type = PpssppModelTargetRegisterContainerAndBank::class
    ),
    TargetAttributeType(type = Void::class)
  ],
  canonicalContainer = true
)
class PpssppModelTargetRegisterContainerAndBank(
  thread: PpssppModelTargetThread,
  private val threadId: Long
) :
  PpssppTargetObject<PpssppModelTargetRegister, PpssppModelTargetThread>(thread.model, thread, REGISTERS_NAME, "RegisterContainer"),
  TargetRegisterContainer, TargetRegisterBank {

  companion object {
    const val REGISTERS_NAME = "Registers"

    private val logger = LogManager.getLogger(PpssppModelTargetRegisterContainerAndBank::class.java)
    private val ppssppVfpuRegisterNameRegex = """v[\da-f]{3}""".toRegex(RegexOption.IGNORE_CASE)
  }

  private val container = this
  private val targetRegisters = mutableMapOf<PpssppCpuRegisterMeta, PpssppModelTargetRegister>()

  init {
    changeAttributes(
      listOf(),
      listOf(),
      mapOf(
        DESCRIPTIONS_ATTRIBUTE_NAME to this
      ),
      UpdateReason.INITIALIZED
    )
  }

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val cpuRegisters = api.listRegisters(threadId)
    val newTargetRegisters = cpuRegisters
      .map { getTargetRegister(mapMetaToSpec(it.meta())) }
    newTargetRegisters.forEachIndexed { index, targetRegister ->
      val register = cpuRegisters[index]
      targetRegister.updateValue(uintValueToBytes(register.uintValue))
    }
    val delta = setElements(newTargetRegisters, UpdateReason.REFRESHED)
    if (!delta.isEmpty) {
      targetRegisters.entries
        .removeIf { delta.removed.containsValue(it.value) }
    }
  }

  private fun getTargetRegister(register: PpssppCpuRegisterMeta): PpssppModelTargetRegister {
    return targetRegisters.getOrPut(register) { PpssppModelTargetRegister(this, register) }
  }

  override fun readRegistersNamed(names: Collection<String>) = modelScope.future {
    val values = api.listRegisters(threadId)
      .filter { names.contains(mapPpssppRegisterNameToSpec(it.name)) }
      .associateBy({ mapPpssppRegisterNameToSpec(it.name) }, { uintValueToBytes(it.uintValue) })
    values.forEach { (registerName, value) ->
      val entry = targetRegisters.entries.firstOrNull { it.key.name == registerName }
        ?: return@forEach
      val (_, targetRegister) = entry
      targetRegister.updateValue(value)
    }
    listeners.fire.registersUpdated(container, values)
    values
  }

  override fun writeRegistersNamed(values: Map<String, ByteArray>) = modelScope.futureVoid {
    values.forEach { (registerName, value) ->
      val entry = targetRegisters.entries.firstOrNull { it.key.name == registerName }
      if (entry == null) {
        logger.warn("Register $registerName cannot be written to")
        return@forEach
      }
      val (meta, targetRegister) = entry
      api.setRegister(threadId, meta.categoryId, meta.id, "0x${BigInteger(1, value).toString(16)}")
      targetRegister.updateValue(value)
    }
    listeners.fire.registersUpdated(container, values)
  }

  private fun uintValueToBytes(uintValue: Long): ByteArray {
    val buffer = ByteBuffer.allocate(8)
    buffer.putLong(uintValue)
    return buffer.array()
  }

  private fun mapMetaToSpec(meta: PpssppCpuRegisterMeta): PpssppCpuRegisterMeta {
    return meta.copy(name = mapPpssppRegisterNameToSpec(meta.name))
  }

  private fun mapPpssppRegisterNameToSpec(name: String): String {
    return when {
      name.matches(ppssppVfpuRegisterNameRegex) -> {
        val registerId = name.substringAfter("v").toInt(16)
        return "V${"%02X".format(registerId)}"
      }
      else -> name
    }
  }
}
