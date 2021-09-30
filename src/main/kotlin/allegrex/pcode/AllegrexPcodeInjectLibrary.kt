package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.lang.PcodeInjectLibrary

class AllegrexPcodeInjectLibrary : PcodeInjectLibrary {
  companion object {
    private const val VFPU_LOAD_Q = "vfpuLoadQ"
    private const val VFPU_LOAD_Q_PART = "vfpuLoadQPart"
    private const val VFPU_SAVE_Q_PART = "vfpuSaveQPart"
    private const val VFPU_READ_P = "vfpuReadP"
    private const val VFPU_WRITE_P = "vfpuWriteP"
    private const val VFPU_READ_T = "vfpuReadT"
    private const val VFPU_WRITE_T = "vfpuWriteT"
    private const val VFPU_READ_Q = "vfpuReadQ"
    private const val VFPU_WRITE_Q = "vfpuWriteQ"
    private const val VFPU_READ_MATRIX_2 = "vfpuReadMatrix2"
    private const val VFPU_WRITE_MATRIX_2 = "vfpuWriteMatrix2"
    private const val VFPU_READ_MATRIX_3 = "vfpuReadMatrix3"
    private const val VFPU_WRITE_MATRIX_3 = "vfpuWriteMatrix3"
    private const val VFPU_READ_MATRIX_4 = "vfpuReadMatrix4"
    private const val VFPU_WRITE_MATRIX_4 = "vfpuWriteMatrix4"

    private const val SOURCE_NAME = "allegrexInternal"
  }

  private var implementedOps = mapOf<String, InjectPayloadCallother>()

  @Suppress("unused")
  constructor(lang: SleighLanguage) : super(lang) {
    val ops = mutableMapOf<String, InjectPayloadCallother>()
    ops[VFPU_LOAD_Q] = InjectVfpuLoadQ(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_LOAD_Q_PART] = InjectVfpuLoadQPart(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_SAVE_Q_PART] = InjectVfpuSaveQPart(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_READ_P] = InjectVfpuReadP(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_WRITE_P] = InjectVfpuWriteP(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_READ_T] = InjectVfpuReadT(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_WRITE_T] = InjectVfpuWriteT(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_READ_Q] = InjectVfpuReadQ(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_WRITE_Q] = InjectVfpuWriteQ(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_READ_MATRIX_4] = InjectVfpuReadMatrix4(SOURCE_NAME, language, uniqueBase, uniqueAllocate(0x300))
    ops[VFPU_WRITE_MATRIX_4] = InjectVfpuWriteMatrix4(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    implementedOps = ops
  }

  constructor(library: AllegrexPcodeInjectLibrary) : super(library) {
    implementedOps = library.implementedOps
  }

  private fun uniqueAllocate(size: Int = 0x100): Long {
    uniqueBase += size
    return uniqueBase
  }

  override fun clone(): PcodeInjectLibrary {
    return AllegrexPcodeInjectLibrary(this)
  }

  override fun allocateInject(sourceName: String, name: String, tp: Int): InjectPayload {
    val payload = implementedOps[name]
    return when {
      tp == InjectPayload.CALLOTHERFIXUP_TYPE && payload != null -> payload
      else -> super.allocateInject(sourceName, name, tp)
    }
  }
}
