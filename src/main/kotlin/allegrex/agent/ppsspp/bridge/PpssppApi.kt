package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.PpssppCpuBreakpoint
import allegrex.agent.ppsspp.bridge.model.PpssppCpuRegister
import allegrex.agent.ppsspp.bridge.model.PpssppCpuStatus
import allegrex.agent.ppsspp.bridge.model.PpssppGameStatus
import allegrex.agent.ppsspp.bridge.model.PpssppHleThread
import allegrex.agent.ppsspp.bridge.model.PpssppMemoryBreakpoint
import allegrex.agent.ppsspp.bridge.model.PpssppMemoryRange
import allegrex.agent.ppsspp.bridge.model.PpssppStackFrame
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuBreakpointAddEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuBreakpointListEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuBreakpointRemoveEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuRegistersEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuStatusEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppGameStatusEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppHleBacktraceEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppHleThreadsListEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryBreakpointAddEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryBreakpointListEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryBreakpointRemoveEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryMappingEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryReadEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppSetRegisterEvent
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuBreakpointAddRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuBreakpointListRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuBreakpointRemoveRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuGetRegistersRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuResumeRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuStatusRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuStepIntoRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuStepOutRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuStepOverRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuSteppingRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppGameStatusRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppHleBacktraceRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppHleThreadsListRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryBreakpointAddRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryBreakpointListRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryBreakpointRemoveRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryMappingRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryReadRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryWriteRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppSetRegisterRequest
import java.util.Base64

class PpssppApi(val bridge: PpssppBridge) {
  suspend fun gameStatus(): PpssppGameStatus {
    return bridge.sendRequestAndWait<PpssppGameStatusEvent>(PpssppGameStatusRequest())
      .toGameStatus()
  }

  suspend fun cpuStatus(): PpssppCpuStatus {
    return bridge.sendRequestAndWait<PpssppCpuStatusEvent>(PpssppCpuStatusRequest())
      .toCpuStatus()
  }

  suspend fun resume() {
    bridge.sendRequest(PpssppCpuResumeRequest())
  }

  suspend fun stepping() {
    bridge.sendRequest(PpssppCpuSteppingRequest())
  }

  suspend fun stepInto(threadId: Int) {
    bridge.sendRequest(PpssppCpuStepIntoRequest(threadId))
  }

  suspend fun stepOver(threadId: Int) {
    bridge.sendRequest(PpssppCpuStepOverRequest(threadId))
  }

  suspend fun stepOut(threadId: Int) {
    bridge.sendRequest(PpssppCpuStepOutRequest(threadId))
  }

  suspend fun listRegisters(threadId: Int): List<PpssppCpuRegister> {
    return bridge.sendRequestAndWait<PpssppCpuRegistersEvent>(PpssppCpuGetRegistersRequest(threadId))
      .getRegisters(threadId)
  }

  suspend fun setRegister(threadId: Int, category: Int, registerId: Int, value: String) {
    bridge.sendRequestAndWait<PpssppSetRegisterEvent>(PpssppSetRegisterRequest(threadId, category, registerId, value))
  }

  suspend fun listThreads(): List<PpssppHleThread> {
    return bridge.sendRequestAndWait<PpssppHleThreadsListEvent>(PpssppHleThreadsListRequest())
      .threads
  }

  suspend fun backtraceThread(threadId: Int): List<PpssppStackFrame> {
    return bridge.sendRequestAndWait<PpssppHleBacktraceEvent>(PpssppHleBacktraceRequest(threadId))
      .frames
  }

  suspend fun addCpuBreakpoint(
    address: Long,
    enabled: Boolean = true,
    log: Boolean = false,
    condition: String? = null,
    logFormat: String? = null
  ) {
    bridge.sendRequestAndWait<PpssppCpuBreakpointAddEvent>(
      PpssppCpuBreakpointAddRequest(address, enabled, log, condition, logFormat)
    )
  }

  suspend fun removeCpuBreakpoint(address: Long) {
    bridge.sendRequestAndWait<PpssppCpuBreakpointRemoveEvent>(
      PpssppCpuBreakpointRemoveRequest(address)
    )
  }

  suspend fun listCpuBreakpoints(): List<PpssppCpuBreakpoint> {
    return bridge.sendRequestAndWait<PpssppCpuBreakpointListEvent>(PpssppCpuBreakpointListRequest())
      .breakpoints
  }

  suspend fun addMemoryBreakpoint(
    address: Long,
    size: Long,
    enabled: Boolean = true,
    log: Boolean = false,
    read: Boolean = true,
    write: Boolean = true,
    change: Boolean = false,
    logFormat: String? = null
  ) {
    bridge.sendRequestAndWait<PpssppMemoryBreakpointAddEvent>(
      PpssppMemoryBreakpointAddRequest(address, size, enabled, log, read, write, change, logFormat)
    )
  }

  suspend fun removeMemoryBreakpoint(address: Long, size: Long) {
    bridge.sendRequestAndWait<PpssppMemoryBreakpointRemoveEvent>(
      PpssppMemoryBreakpointRemoveRequest(address, size)
    )
  }

  suspend fun listMemoryBreakpoints(): List<PpssppMemoryBreakpoint> {
    return bridge.sendRequestAndWait<PpssppMemoryBreakpointListEvent>(PpssppMemoryBreakpointListRequest())
      .breakpoints
  }

  suspend fun getMemoryMap(): List<PpssppMemoryRange> {
    return bridge.sendRequestAndWait<PpssppMemoryMappingEvent>(PpssppMemoryMappingRequest())
      .ranges
  }

  suspend fun readMemory(offset: Long, length: Int): ByteArray {
    val response = bridge.sendRequestAndWait<PpssppMemoryReadEvent>(PpssppMemoryReadRequest(offset, length))
    return Base64.getDecoder().decode(response.base64)
  }

  suspend fun writeMemory(offset: Long, data: ByteArray) {
    val encodedData = Base64.getEncoder().encodeToString(data)
    bridge.sendRequestAndWait<PpssppEvent>(PpssppMemoryWriteRequest(offset, encodedData))
  }
}
