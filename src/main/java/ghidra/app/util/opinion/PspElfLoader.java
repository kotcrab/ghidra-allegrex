package ghidra.app.util.opinion;

import generic.continues.GenericFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.PspElfHeader;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.List;

public class PspElfLoader extends ElfLoader {
	@Override
	public String getName () {
		return "PSP Executable (ELF)";
	}

	@Override
	public LoaderTier getTier () {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority () {
		return 0;
	}

	@Override
	public void load (ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
					  MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws IOException {
		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			ElfHeader elf = PspElfHeader.createElfHeader(factory, provider);
			ElfProgramBuilder.loadElf(elf, program, options, log, handler, monitor);
		} catch (ElfException e) {
			throw new IOException(e.getMessage());
		} catch (CancelledException e) { // TODO: Caller should properly handle CancelledException instead
			throw new IOException(e.getMessage());
		}
	}
}
