package allegrex.agent.ppsspp.bridge.model.event

val ppssppEventMap = mapOf(
  PpssppCpuRegistersEvent.EVENT_NAME to PpssppCpuRegistersEvent::class.java,
  PpssppCpuResumeEvent.EVENT_NAME to PpssppCpuResumeEvent::class.java,
  PpssppCpuSteppingEvent.EVENT_NAME to PpssppCpuSteppingEvent::class.java,
  PpssppHleThreadsEvent.EVENT_NAME to PpssppHleThreadsEvent::class.java,
  PpssppMemoryMapEvent.EVENT_NAME to PpssppMemoryMapEvent::class.java,
  PpssppMemoryReadEvent.EVENT_NAME to PpssppMemoryReadEvent::class.java,
  PpssppMemoryWriteEvent.EVENT_NAME to PpssppMemoryWriteEvent::class.java,
  PpssppSetRegisterEvent.EVENT_NAME to PpssppSetRegisterEvent::class.java,
)
