package allegrex.agent.ppsspp.model

object UpdateReason {
  const val INITIALIZED = "Initialized"
  const val REFRESHED = "Refreshed"
  const val PROCESS_CREATED = "Process created"
  const val PROCESS_EXITED = "Process exited"
  const val FOCUS_CHANGED = "Focus changed"
  const val RUNNING = "Running"
  const val STOPPED = "Stopped"
  const val EXECUTION_STATE_CHANGED = "Execution state change"
  const val STEP_COMPLETED = "Step completed"
}
