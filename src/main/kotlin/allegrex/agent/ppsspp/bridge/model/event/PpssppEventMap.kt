package allegrex.agent.ppsspp.bridge.model.event

val ppssppEventMap = mapOf(
  PpssppCpuBreakpointAddEvent.EVENT_NAME to PpssppCpuBreakpointAddEvent::class.java,
  PpssppCpuBreakpointListEvent.EVENT_NAME to PpssppCpuBreakpointListEvent::class.java,
  PpssppCpuBreakpointRemoveEvent.EVENT_NAME to PpssppCpuBreakpointRemoveEvent::class.java,

  PpssppCpuRegistersEvent.EVENT_NAME to PpssppCpuRegistersEvent::class.java,
  PpssppCpuResumeEvent.EVENT_NAME to PpssppCpuResumeEvent::class.java,
  PpssppCpuStatusEvent.EVENT_NAME to PpssppCpuStatusEvent::class.java,
  PpssppCpuSteppingEvent.EVENT_NAME to PpssppCpuSteppingEvent::class.java,

  PpssppGamePauseEvent.EVENT_NAME to PpssppGamePauseEvent::class.java,
  PpssppGameQuitEvent.EVENT_NAME to PpssppGameQuitEvent::class.java,
  PpssppGameResumeEvent.EVENT_NAME to PpssppGameResumeEvent::class.java,
  PpssppGameStartEvent.EVENT_NAME to PpssppGameStartEvent::class.java,
  PpssppGameStatusEvent.EVENT_NAME to PpssppGameStatusEvent::class.java,

  PpssppHleBacktraceEvent.EVENT_NAME to PpssppHleBacktraceEvent::class.java,
  PpssppHleModuleListEvent.EVENT_NAME to PpssppHleModuleListEvent::class.java,
  PpssppHleThreadsListEvent.EVENT_NAME to PpssppHleThreadsListEvent::class.java,

  PpssppLogEvent.EVENT_NAME to PpssppLogEvent::class.java,

  PpssppMemoryBreakpointAddEvent.EVENT_NAME to PpssppMemoryBreakpointAddEvent::class.java,
  PpssppMemoryBreakpointListEvent.EVENT_NAME to PpssppMemoryBreakpointListEvent::class.java,
  PpssppMemoryBreakpointRemoveEvent.EVENT_NAME to PpssppMemoryBreakpointRemoveEvent::class.java,

  PpssppMemoryMappingEvent.EVENT_NAME to PpssppMemoryMappingEvent::class.java,
  PpssppMemoryReadEvent.EVENT_NAME to PpssppMemoryReadEvent::class.java,
  PpssppMemoryWriteEvent.EVENT_NAME to PpssppMemoryWriteEvent::class.java,

  PpssppSetRegisterEvent.EVENT_NAME to PpssppSetRegisterEvent::class.java,
)
