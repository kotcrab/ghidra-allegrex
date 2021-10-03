package allegrex.pcode

class MatrixMapper(
  private val baseRegId: Int,
  transpose: Boolean,
  val dimSize: Int,
  private val vfpuPcode: VfpuPcode
) {
  private val rowStride = if (transpose) 1 else 4
  private val columnStride = if (transpose) 4 else 1
  val lastDimIndex = dimSize - 1

  fun regNameAt(row: Int, column: Int): String {
    return vfpuPcode.regIdToName(elementAt(row, column))
  }

  private fun elementAt(row: Int, column: Int): Int {
    return baseRegId + rowStride * row + columnStride * column
  }
}
