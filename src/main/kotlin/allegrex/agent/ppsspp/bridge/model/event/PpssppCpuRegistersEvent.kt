package allegrex.agent.ppsspp.bridge.model.event

import allegrex.agent.ppsspp.bridge.model.PpssppCpuRegister
import allegrex.agent.ppsspp.bridge.model.PpssppCpuRegistersCategory
import allegrex.agent.ppsspp.bridge.model.PpssppException

data class PpssppCpuRegistersEvent(
  val categories: List<PpssppCpuRegistersCategory>,
  override val ticket: String?
) : PpssppEvent {
  companion object {
    const val EVENT_NAME = "cpu.getAllRegs"

    private object Category {
      const val GPR = "GPR"
      const val FPU = "FPU"
      const val VFPU = "VFPU"
    }
  }

  override val event: String = EVENT_NAME

  fun getRegisters(associateWithThreadId: Long): List<PpssppCpuRegister> {
    return getGprRegisters(associateWithThreadId) +
      getFpuRegisters(associateWithThreadId) +
      getVfpuRegisters(associateWithThreadId)
  }

  fun getGprRegisters(associateWithThreadId: Long): List<PpssppCpuRegister> {
    return getCategoryByName(Category.GPR).getRegisters(associateWithThreadId)
  }

  fun getFpuRegisters(associateWithThreadId: Long): List<PpssppCpuRegister> {
    return getCategoryByName(Category.FPU).getRegisters(associateWithThreadId)
  }

  fun getVfpuRegisters(associateWithThreadId: Long): List<PpssppCpuRegister> {
    return getCategoryByName(Category.VFPU).getRegisters(associateWithThreadId)
  }

  private fun getCategoryByName(name: String): PpssppCpuRegistersCategory {
    return categories.firstOrNull { it.name.equals(name, ignoreCase = true) }
      ?: throw PpssppException("No such register category: $name")
  }
}
