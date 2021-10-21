package allegrex.agent.ppsspp.model

import allegrex.agent.ppsspp.client.model.PpssppCpuRegisterMeta
import allegrex.agent.ppsspp.util.futureVoid
import ghidra.dbg.target.TargetRegister
import ghidra.dbg.target.TargetRegisterBank
import ghidra.dbg.target.TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME
import ghidra.dbg.target.TargetRegisterContainer
import ghidra.dbg.target.schema.TargetAttributeType
import ghidra.dbg.target.schema.TargetElementType
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode
import ghidra.dbg.target.schema.TargetObjectSchemaInfo
import kotlinx.coroutines.future.future
import java.util.concurrent.ConcurrentHashMap

// TODO

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
    const val REGISTERS_NAME = "Registers" // TODO support mapped VFPU
  }

  // TODO switch to normal map
  private val registerObjects = ConcurrentHashMap<PpssppCpuRegisterMeta, PpssppModelTargetRegister>()

  init {
    changeAttributes(
      listOf(),
      listOf(),
      mapOf(
        DESCRIPTIONS_ATTRIBUTE_NAME to this
      ),
      "Initialized"
    )
    requestElements(false)
  }

  override fun requestElements(refresh: Boolean) = modelScope.futureVoid {
    val gprRegisters = api.listRegisters(threadId)
    val registers = gprRegisters
      .map { getTargetRegister(it.meta()) }
    registers.forEachIndexed { index, register ->
      val reg = gprRegisters[index]
      register.changeAttributes(
        emptyList(), emptyList(), mapOf(
          TargetRegister.VALUE_ATTRIBUTE_NAME to reg.uintValue.toString(16),
          TargetRegister.DISPLAY_ATTRIBUTE_NAME to "${reg.meta().name}: ${reg.uintValue.toString(16)}",
        ),
        "Refreshed"
      )
    }
    setElements(registers, "Refreshed") // delta.removed ignored, registers won't change // TODO thread can get removed
  }

  private fun getTargetRegister(register: PpssppCpuRegisterMeta): PpssppModelTargetRegister {
    return registerObjects.getOrPut(register) { PpssppModelTargetRegister(this, register) }
  }

  override fun readRegistersNamed(names: Collection<String>) = modelScope.future {
    // TODO readRegistersNamed
    println("WARN: Register read attempt")
    emptyMap<String, ByteArray>()
  }

  override fun writeRegistersNamed(values: Map<String, ByteArray>) = modelScope.futureVoid {
    // TODO writeRegistersNamed
    println("WARN: Register write attempt")
  }
}
