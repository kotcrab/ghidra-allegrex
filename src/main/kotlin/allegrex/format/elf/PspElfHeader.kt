package allegrex.format.elf

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.elf.ElfHeader
import java.util.function.Consumer

open class PspElfHeader(
  provider: ByteProvider,
  val useRebootBinTypeBMapping: Boolean,
  errorConsumer: Consumer<String>,
) : ElfHeader(provider, errorConsumer)
