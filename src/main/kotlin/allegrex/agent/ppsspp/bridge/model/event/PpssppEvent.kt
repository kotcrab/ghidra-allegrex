package allegrex.agent.ppsspp.bridge.model.event

interface PpssppEvent {
  val ticket: String?
  val event: String
}
