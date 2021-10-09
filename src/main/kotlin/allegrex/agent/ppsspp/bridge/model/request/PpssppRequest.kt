package allegrex.agent.ppsspp.bridge.model.request

interface PpssppRequest {
  val ticket: String?
  val event: String
}
