package allegrex.agent.ppsspp.client.model.request

interface PpssppRequest {
  val ticket: String?
  val event: String
}
