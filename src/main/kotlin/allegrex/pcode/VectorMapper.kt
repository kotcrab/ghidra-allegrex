package allegrex.pcode

class VectorMapper(
  private val baseRegId: Int,
  transpose: Boolean,
  val size: Int,
  private val vfpuPcode: VfpuPcode
) {
  private val stride = if (transpose) 1 else 4
  val lastIndex = size - 1

  fun regNameAt(index: Int): String {
    return vfpuPcode.regIdToName(elementAt(index))
  }

  private fun elementAt(index: Int): Int {
    return baseRegId + stride * index
  }
}
