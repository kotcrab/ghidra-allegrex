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

    private const val SOURCE_NAME = "allegrexInternal"
  }

  private var implementedOps = mapOf<String, InjectPayloadCallother>()

  @Suppress("unused")
  constructor(lang: SleighLanguage) : super(lang) {
    val ops = mutableMapOf<String, InjectPayloadCallother>()
    ops[VFPU_LOAD_Q] = InjectVfpuLoadQ(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_LOAD_Q_PART] = InjectVfpuLoadQPart(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_SAVE_Q_PART] = InjectVfpuSaveQPart(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_READ_P] = InjectVfpuReadP(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_WRITE_P] = InjectVfpuWriteP(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_READ_T] = InjectVfpuReadT(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_WRITE_T] = InjectVfpuWriteT(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_READ_Q] = InjectVfpuReadQ(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    ops[VFPU_WRITE_Q] = InjectVfpuWriteQ(SOURCE_NAME, language, uniqueBase)
    uniqueBase += 0x100
    implementedOps = ops
  }

  constructor(library: AllegrexPcodeInjectLibrary) : super(library) {
    implementedOps = library.implementedOps
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
