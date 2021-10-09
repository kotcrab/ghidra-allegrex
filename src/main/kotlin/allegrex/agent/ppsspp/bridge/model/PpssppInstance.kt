package allegrex.agent.ppsspp.bridge.model

import com.google.gson.annotations.SerializedName

data class PpssppInstance(
  val ip: String,
  @SerializedName("p")
  val port: Int
)
