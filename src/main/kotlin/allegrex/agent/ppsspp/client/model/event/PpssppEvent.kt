package allegrex.agent.ppsspp.client.model.event

interface PpssppEvent {
  val ticket: String?
  val event: String
}
