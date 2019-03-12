/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;

public class Allegrex_ElfRelocation extends ElfRelocation {
	private int addres;
	private int type;
	private int offsetIndex;
	private int relocateToIndex;

	/** DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD. */
	public Allegrex_ElfRelocation () {
	}

	@Override
	protected void initElfRelocation (FactoryBundledWithBinaryReader reader, ElfHeader elfHeader,
									  int relocationTableIndex, boolean withAddend) throws IOException {
		super.initElfRelocation(reader, elfHeader, relocationTableIndex, withAddend);
		addres = (int) getOffset();
		int relloc = (int) getRelocationInfo();
		type = relloc & 0xFF;
		offsetIndex = relloc >> 8 & 0xFF;
		relocateToIndex = relloc >> 16 & 0xFF;

//		if (elfHeader.isLittleEndian()) {
//			// revert to big-endian byte order
//			info = DataConverter.swapBytes(info, 8);
//		}
//		DataConverter converter = elfHeader.isLittleEndian() ? LittleEndianDataConverter.INSTANCE
//				: BigEndianDataConverter.INSTANCE;
//		byte[] rSymBytes = BigEndianDataConverter.INSTANCE.getBytes((int) (info >>> 32));
//		symbolIndex = converter.getInt(rSymBytes);
//		specialSymbolIndex = ((int) info >>> 24) & 0xff;
//		type = (int) info & 0xffffff;
	}

	@Override
	public int getSymbolIndex () {
		return 0; // TODO return offsetIndex?
	}

	@Override
	public int getType () {
		return type;
	}

	@Override
	public DataType toDataType () {
		String dtName = "Elf32_Allegrex_Rel";
		Structure struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		struct.add(DWORD, "r_address", null);
		struct.add(BYTE, "r_type", null);
		struct.add(BYTE, "r_offsetIndex", null);
		struct.add(BYTE, "r_relocateToIndex", null);
		return struct;
	}
}
