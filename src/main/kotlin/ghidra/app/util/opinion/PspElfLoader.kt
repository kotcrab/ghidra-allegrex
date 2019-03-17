package ghidra.app.util.opinion

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.elf.ElfException
import ghidra.app.util.bin.format.elf.PspElfHeader
import ghidra.app.util.importer.MemoryConflictHandler
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.MessageLogContinuesFactory
import ghidra.program.model.listing.Program
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import java.io.IOException

class PspElfLoader : ElfLoader() {
    companion object {
        const val PSP_ELF_NAME = "PSP Executable (ELF)"
    }

    override fun getName(): String {
        return PSP_ELF_NAME
    }

    override fun getTier(): LoaderTier {
        return LoaderTier.SPECIALIZED_TARGET_LOADER
    }

    override fun getTierPriority(): Int {
        return 0
    }

    override fun load(
        provider: ByteProvider, loadSpec: LoadSpec?, options: List<Option>,
        program: Program,
        handler: MemoryConflictHandler, monitor: TaskMonitor, log: MessageLog
    ) {
        try {
            val factory = MessageLogContinuesFactory.create(log)
            val elf = PspElfHeader.createElfHeader(factory, provider)
            ElfProgramBuilder.loadElf(elf, program, options, log, handler, monitor)
            program.executableFormat = PSP_ELF_NAME
        } catch (e: ElfException) {
            throw IOException(e.message)
        } catch (e: CancelledException) { // TODO: Caller should properly handle CancelledException instead
            throw IOException(e.message)
        }
    }
}
