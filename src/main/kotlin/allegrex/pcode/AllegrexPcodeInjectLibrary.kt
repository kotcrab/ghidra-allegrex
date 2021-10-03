package allegrex.pcode

import ghidra.app.plugin.processors.sleigh.SleighLanguage
import ghidra.program.model.lang.InjectPayload
import ghidra.program.model.lang.InjectPayloadCallother
import ghidra.program.model.lang.PcodeInjectLibrary
import ghidra.program.model.pcode.Varnode

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
    val pairMapper = { vfpuPcode: VfpuPcode, baseReg: Varnode -> vfpuPcode.mapBaseRegToModePair(baseReg) }
    val tripleMapper = { vfpuPcode: VfpuPcode, baseReg: Varnode -> vfpuPcode.mapBaseRegToModeTriple(baseReg) }
    val quadMapper = { vfpuPcode: VfpuPcode, baseReg: Varnode -> vfpuPcode.mapBaseRegToModeQuad(baseReg) }
    val matrix2Mapper = { vfpuPcode: VfpuPcode, baseReg: Varnode, transpose: Boolean -> vfpuPcode.mapBaseRegToModeMatrix2(baseReg, transpose) }
    val matrix3Mapper = { vfpuPcode: VfpuPcode, baseReg: Varnode, transpose: Boolean -> vfpuPcode.mapBaseRegToModeMatrix3(baseReg, transpose) }
    val matrix4Mapper = { vfpuPcode: VfpuPcode, baseReg: Varnode, transpose: Boolean -> vfpuPcode.mapBaseRegToModeMatrix4(baseReg, transpose) }

    val ops = mutableMapOf<String, InjectPayloadCallother>()
    ops[VFPU_LOAD_Q] = InjectVfpuLoadQ(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_LOAD_Q_PART] = InjectVfpuLoadQPart(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_SAVE_Q_PART] = InjectVfpuSaveQPart(SOURCE_NAME, language, uniqueBase, uniqueAllocate())
    ops[VFPU_READ_P] = InjectVfpuReadVector(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), pairMapper)
    ops[VFPU_WRITE_P] = InjectVfpuWriteVector(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), pairMapper)
    ops[VFPU_READ_T] = InjectVfpuReadVector(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), tripleMapper)
    ops[VFPU_WRITE_T] = InjectVfpuWriteVector(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), tripleMapper)
    ops[VFPU_READ_Q] = InjectVfpuReadVector(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), quadMapper)
    ops[VFPU_WRITE_Q] = InjectVfpuWriteVector(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), quadMapper)
    ops[VFPU_READ_MATRIX_2] = InjectVfpuReadMatrix(SOURCE_NAME, language, uniqueBase, uniqueAllocate(0x300), matrix2Mapper)
    ops[VFPU_READ_MATRIX_3] = InjectVfpuReadMatrix(SOURCE_NAME, language, uniqueBase, uniqueAllocate(0x300), matrix3Mapper)
    ops[VFPU_READ_MATRIX_4] = InjectVfpuReadMatrix(SOURCE_NAME, language, uniqueBase, uniqueAllocate(0x300), matrix4Mapper)
    ops[VFPU_WRITE_MATRIX_2] = InjectVfpuWriteMatrixRow(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), matrix2Mapper)
    ops[VFPU_WRITE_MATRIX_3] = InjectVfpuWriteMatrixRow(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), matrix3Mapper)
    ops[VFPU_WRITE_MATRIX_4] = InjectVfpuWriteMatrixRow(SOURCE_NAME, language, uniqueBase, uniqueAllocate(), matrix4Mapper)
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
