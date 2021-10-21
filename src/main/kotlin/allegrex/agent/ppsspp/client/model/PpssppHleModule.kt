package allegrex.agent.ppsspp.client.model

import com.google.gson.annotations.SerializedName

data class PpssppHleModule(
  val name: String,
  val address: Long,
  val size: Long,
  @SerializedName("isActive")
  val active: Boolean,
) {
  fun meta() = PpssppHleModuleMeta(name, address, size)
}
