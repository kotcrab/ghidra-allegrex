package allegrex.agent.ppsspp.client

import allegrex.agent.ppsspp.client.model.PpssppCpuBreakpoint
import allegrex.agent.ppsspp.client.model.PpssppCpuRegister
import allegrex.agent.ppsspp.client.model.PpssppCpuStatus
import allegrex.agent.ppsspp.client.model.PpssppGameStatus
import allegrex.agent.ppsspp.client.model.PpssppHleFunction
import allegrex.agent.ppsspp.client.model.PpssppHleModule
import allegrex.agent.ppsspp.client.model.PpssppHleThread
import allegrex.agent.ppsspp.client.model.PpssppMemoryBreakpoint
import allegrex.agent.ppsspp.client.model.PpssppMemoryRange
import allegrex.agent.ppsspp.client.model.PpssppStackFrame
import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointAddEvent
import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointListEvent
import allegrex.agent.ppsspp.client.model.event.PpssppCpuBreakpointRemoveEvent
import allegrex.agent.ppsspp.client.model.event.PpssppCpuRegistersEvent
import allegrex.agent.ppsspp.client.model.event.PpssppCpuStatusEvent
import allegrex.agent.ppsspp.client.model.event.PpssppEvent
import allegrex.agent.ppsspp.client.model.event.PpssppGameStatusEvent
import allegrex.agent.ppsspp.client.model.event.PpssppHleBacktraceEvent
import allegrex.agent.ppsspp.client.model.event.PpssppHleFunctionListEvent
import allegrex.agent.ppsspp.client.model.event.PpssppHleModuleListEvent
import allegrex.agent.ppsspp.client.model.event.PpssppHleThreadsListEvent
import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointAddEvent
import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointListEvent
import allegrex.agent.ppsspp.client.model.event.PpssppMemoryBreakpointRemoveEvent
import allegrex.agent.ppsspp.client.model.event.PpssppMemoryMappingEvent
import allegrex.agent.ppsspp.client.model.event.PpssppMemoryReadEvent
import allegrex.agent.ppsspp.client.model.event.PpssppSetRegisterEvent
import allegrex.agent.ppsspp.client.model.request.PpssppCpuBreakpointAddRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuBreakpointListRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuBreakpointRemoveRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuGetRegistersRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuResumeRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuStatusRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuStepIntoRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuStepOutRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuStepOverRequest
import allegrex.agent.ppsspp.client.model.request.PpssppCpuSteppingRequest
import allegrex.agent.ppsspp.client.model.request.PpssppGameStatusRequest
import allegrex.agent.ppsspp.client.model.request.PpssppHleBacktraceRequest
import allegrex.agent.ppsspp.client.model.request.PpssppHleFunctionListRequest
import allegrex.agent.ppsspp.client.model.request.PpssppHleModuleListRequest
import allegrex.agent.ppsspp.client.model.request.PpssppHleThreadsListRequest
import allegrex.agent.ppsspp.client.model.request.PpssppMemoryBreakpointAddRequest
import allegrex.agent.ppsspp.client.model.request.PpssppMemoryBreakpointListRequest
import allegrex.agent.ppsspp.client.model.request.PpssppMemoryBreakpointRemoveRequest
import allegrex.agent.ppsspp.client.model.request.PpssppMemoryMappingRequest
import allegrex.agent.ppsspp.client.model.request.PpssppMemoryReadRequest
import allegrex.agent.ppsspp.client.model.request.PpssppMemoryWriteRequest
import allegrex.agent.ppsspp.client.model.request.PpssppSetRegisterRequest
import java.util.Base64

class PpssppApi(private val client: PpssppClient) {
  suspend fun gameStatus(): PpssppGameStatus {
    return client.sendRequestAndWait<PpssppGameStatusEvent>(PpssppGameStatusRequest())
      .toGameStatus()
  }

  suspend fun cpuStatus(): PpssppCpuStatus {
    return client.sendRequestAndWait<PpssppCpuStatusEvent>(PpssppCpuStatusRequest())
      .toCpuStatus()
  }

  suspend fun resume() {
    client.sendRequest(PpssppCpuResumeRequest())
  }

  suspend fun stepping() {
    client.sendRequest(PpssppCpuSteppingRequest())
  }

  suspend fun stepInto(threadId: Long) {
    client.sendRequest(PpssppCpuStepIntoRequest(threadId))
  }

  suspend fun stepOver(threadId: Long) {
    client.sendRequest(PpssppCpuStepOverRequest(threadId))
  }

  suspend fun stepOut(threadId: Long) {
    client.sendRequest(PpssppCpuStepOutRequest(threadId))
  }

  suspend fun listRegisters(threadId: Long): List<PpssppCpuRegister> {
    return client.sendRequestAndWait<PpssppCpuRegistersEvent>(PpssppCpuGetRegistersRequest(threadId))
      .getRegisters(threadId)
  }

  suspend fun setRegister(threadId: Long, category: Int, registerId: Int, value: String) {
    client.sendRequestAndWait<PpssppSetRegisterEvent>(PpssppSetRegisterRequest(threadId, category, registerId, value))
  }

  suspend fun listFunctions(): List<PpssppHleFunction> {
    return client.sendRequestAndWait<PpssppHleFunctionListEvent>(PpssppHleFunctionListRequest())
      .functions
  }

  suspend fun listModules(): List<PpssppHleModule> {
    return client.sendRequestAndWait<PpssppHleModuleListEvent>(PpssppHleModuleListRequest())
      .modules
  }

  suspend fun listThreads(): List<PpssppHleThread> {
    return client.sendRequestAndWait<PpssppHleThreadsListEvent>(PpssppHleThreadsListRequest())
      .threads
  }

  suspend fun backtraceThread(threadId: Long): List<PpssppStackFrame> {
    return client.sendRequestAndWait<PpssppHleBacktraceEvent>(PpssppHleBacktraceRequest(threadId))
      .frames
  }

  suspend fun addCpuBreakpoint(
    address: Long,
    enabled: Boolean = true,
    log: Boolean = false,
    condition: String? = null,
    logFormat: String? = null
  ) {
    client.sendRequestAndWait<PpssppCpuBreakpointAddEvent>(
      PpssppCpuBreakpointAddRequest(address, enabled, log, condition, logFormat)
    )
  }

  suspend fun removeCpuBreakpoint(address: Long) {
    client.sendRequestAndWait<PpssppCpuBreakpointRemoveEvent>(
      PpssppCpuBreakpointRemoveRequest(address)
    )
  }

  suspend fun listCpuBreakpoints(): List<PpssppCpuBreakpoint> {
    return client.sendRequestAndWait<PpssppCpuBreakpointListEvent>(PpssppCpuBreakpointListRequest())
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
    client.sendRequestAndWait<PpssppMemoryBreakpointAddEvent>(
      PpssppMemoryBreakpointAddRequest(address, size, enabled, log, read, write, change, logFormat)
    )
  }

  suspend fun removeMemoryBreakpoint(address: Long, size: Long) {
    client.sendRequestAndWait<PpssppMemoryBreakpointRemoveEvent>(
      PpssppMemoryBreakpointRemoveRequest(address, size)
    )
  }

  suspend fun listMemoryBreakpoints(): List<PpssppMemoryBreakpoint> {
    return client.sendRequestAndWait<PpssppMemoryBreakpointListEvent>(PpssppMemoryBreakpointListRequest())
      .breakpoints
  }

  suspend fun getMemoryMap(): List<PpssppMemoryRange> {
    return client.sendRequestAndWait<PpssppMemoryMappingEvent>(PpssppMemoryMappingRequest())
      .ranges
  }

  suspend fun readMemory(offset: Long, length: Long): ByteArray {
    val response = client.sendRequestAndWait<PpssppMemoryReadEvent>(PpssppMemoryReadRequest(offset, length))
    return Base64.getDecoder().decode(response.base64)
  }

  suspend fun writeMemory(offset: Long, data: ByteArray) {
    val encodedData = Base64.getEncoder().encodeToString(data)
    client.sendRequestAndWait<PpssppEvent>(PpssppMemoryWriteRequest(offset, encodedData))
  }
}
