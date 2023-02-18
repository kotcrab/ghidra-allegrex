package ghidra.app.util.bin.format.elf

import ghidra.app.util.bin.ByteProvider
import java.util.function.Consumer

open class PspElfHeader(
  provider: ByteProvider,
  val useRebootBinTypeBMapping: Boolean,
  errorConsumer: Consumer<String>,
) : ElfHeader(provider, errorConsumer) {

  override fun e_machine(): Short {
    return PspElfConstants.EM_MIPS_PSP_HACK
  }
}
