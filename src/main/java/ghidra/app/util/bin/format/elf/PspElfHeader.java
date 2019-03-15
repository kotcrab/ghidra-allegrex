package ghidra.app.util.bin.format.elf;

import com.kotcrab.ghidra.allegrex.format.elf.PspElfConstants;
import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Msg;
import org.apache.commons.lang3.reflect.FieldUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

public class PspElfHeader extends ElfHeader {
	public static ElfHeader createElfHeader (GenericFactory factory, ByteProvider provider) throws ElfException {
		PspElfHeader elfHeader = (PspElfHeader) factory.create(PspElfHeader.class);
		elfHeader.initElfHeader(factory, provider);
		return elfHeader;
	}

	@Override
	public void parse () throws IOException {
		super.parse();
		parsePspRelocationTables();
	}

	private void parsePspRelocationTables () throws IOException {
		ArrayList<ElfRelocationTable> relocationTableList = new ArrayList<>(Arrays.asList(getRelocationTables()));
		for (ElfSectionHeader section : getSections()) {
			parseSectionBasedRelocationTable(section, relocationTableList);
		}

		var relocationTables = new ElfRelocationTable[relocationTableList.size()];
		relocationTableList.toArray(relocationTables);

		try {
			FieldUtils.writeField(this, "relocationTables", relocationTables, true);
		} catch (IllegalAccessException e) {
			Msg.error(this, "Failed to update PSP ELF relocation list: " + e.getMessage() + " " + e.getClass().getSimpleName());
			e.printStackTrace();
		}
	}

	private void parseSectionBasedRelocationTable (ElfSectionHeader section,
												   ArrayList<ElfRelocationTable> relocationTableList) throws IOException {
		try {
			int sectionHeaderType = section.getType();
			if (sectionHeaderType == PspElfConstants.INSTANCE.getSHT_PSP_REL()) {
				int link = section.getLink(); // section index of associated symbol table
				int info = section.getInfo(); // section index of section to which relocations apply (relocation offset base)

				ElfSectionHeader sectionToBeRelocated = info != 0 ? getSections()[info] : null;
				String relocaBaseName = sectionToBeRelocated != null ? sectionToBeRelocated.getNameAsString() : "PT_LOAD";

				ElfSymbolTable symbolTable = getSymbolTable(getSections()[link]);

				Msg.debug(this,
						"Elf relocation table section " + section.getNameAsString() +
								" affecting " + relocaBaseName);

				relocationTableList.add(ElfRelocationTable.createElfRelocationTable((FactoryBundledWithBinaryReader) getReader(), this,
						section, section.getOffset(), section.getAddress(), section.getSize(),
						section.getEntrySize(), false, symbolTable, sectionToBeRelocated));
			}
		} catch (ArrayIndexOutOfBoundsException e) { // TODO this isn't great...
			Msg.error(this, "Failed to process PSP relocation section " + section.getNameAsString() +
					": " + e.getMessage());
		}
	}

	@Override
	public boolean isRelocatable () {
		//TODO should PRX be relocatable? probably not, it messes up sections virtual addresses (ElfProgramBuilder#processSectionHeaders)
		return super.isRelocatable(); // || e_type() == PspElfConstants.ET_PSP_PRX;
	}

	@Override
	public short e_machine () {
		return PspElfConstants.INSTANCE.getEM_MIPS_PSP_HACK();
	}
}
