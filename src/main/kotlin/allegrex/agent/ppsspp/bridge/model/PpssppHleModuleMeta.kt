package allegrex.agent.ppsspp.bridge.model

import com.google.gson.annotations.SerializedName

data class PpssppHleModuleMeta(
  val name: String,
  val address: Long,
  val size: Long
) : PpssppModelKey
