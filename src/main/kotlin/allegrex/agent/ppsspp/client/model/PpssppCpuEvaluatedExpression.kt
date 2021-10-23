package allegrex.agent.ppsspp.client.model

data class PpssppCpuEvaluatedExpression(
  val expression: String,
  val uintValue: Long,
  val floatValue: String,
)
