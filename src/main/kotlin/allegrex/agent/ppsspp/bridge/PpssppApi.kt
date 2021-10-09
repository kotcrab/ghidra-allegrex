package allegrex.agent.ppsspp.bridge

import allegrex.agent.ppsspp.bridge.model.PpssppCpuRegister
import allegrex.agent.ppsspp.bridge.model.PpssppHleThread
import allegrex.agent.ppsspp.bridge.model.PpssppMemoryRange
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuRegistersEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuResumeEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppCpuSteppingEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppHleThreadsEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryMapEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppMemoryReadEvent
import allegrex.agent.ppsspp.bridge.model.event.PpssppSetRegisterEvent
import allegrex.agent.ppsspp.bridge.model.request.PpssppBasicRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppCpuGetRegistersRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryReadRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppMemoryWriteRequest
import allegrex.agent.ppsspp.bridge.model.request.PpssppSetRegisterRequest
import java.util.Base64

class PpssppApi(val bridge: PpssppBridge) {
  suspend fun resume() {
    bridge.sendRequest(PpssppBasicRequest(PpssppCpuResumeEvent.EVENT_NAME))
  }

  suspend fun stepping() {
    bridge.sendRequest(PpssppBasicRequest(PpssppCpuSteppingEvent.EVENT_NAME))
  }

  suspend fun listRegisters(threadId: Int): List<PpssppCpuRegister> {
    return bridge.sendRequestAndWait<PpssppCpuRegistersEvent>(PpssppCpuGetRegistersRequest(threadId))
      .getRegisters(threadId)
  }

  suspend fun setRegister(threadId: Int, category: Int, registerId: Int, value: String) {
    bridge.sendRequestAndWait<PpssppSetRegisterEvent>(PpssppSetRegisterRequest(threadId, category, registerId, value))
  }

  suspend fun listThreads(): List<PpssppHleThread> {
    return bridge.sendRequestAndWait<PpssppHleThreadsEvent>(PpssppBasicRequest(PpssppHleThreadsEvent.EVENT_NAME))
      .threads
  }

  suspend fun getMemoryMap(): List<PpssppMemoryRange> {
    return bridge.sendRequestAndWait<PpssppMemoryMapEvent>(PpssppBasicRequest(PpssppMemoryMapEvent.EVENT_NAME))
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
