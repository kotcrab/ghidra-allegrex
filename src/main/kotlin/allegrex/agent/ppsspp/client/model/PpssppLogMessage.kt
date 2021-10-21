package allegrex.agent.ppsspp.client.model

data class PpssppLogMessage(
  val timestamp: String,
  val header: String,
  val message: String,
  val level: Int,
  val channel: String,
) {
  object LogLevel {
    const val NOTICE = 1
    const val ERROR = 2
    const val WARNING = 3
    const val INFO = 4
    const val DEBUG = 5
    const val VERBOSE = 6
  }

  fun isError(): Boolean {
    return level == LogLevel.ERROR
  }

  fun asFormattedMessage(): String {
    return "$timestamp $header $message"
  }
}
