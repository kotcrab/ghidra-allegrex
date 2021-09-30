package allegrex.pcode

class Matrix4Mapper(val baseRegId: Int, transpose: Boolean) {
  private val rowStride = if (transpose) 1 else 4
  private val columnStride = if (transpose) 4 else 1

  fun elementAt(row: Int, column: Int): Int {
    return baseRegId + rowStride * row + columnStride * column
  }
}
