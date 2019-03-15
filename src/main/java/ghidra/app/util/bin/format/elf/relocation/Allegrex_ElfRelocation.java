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
	private int type;
	private int sectOffsetIndex;
	private int relocateToIndex;

	/** DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD. */
	public Allegrex_ElfRelocation () {
	}

	@Override
	protected void initElfRelocation (FactoryBundledWithBinaryReader reader, ElfHeader elfHeader,
									  int relocationTableIndex, boolean withAddend) throws IOException {
		super.initElfRelocation(reader, elfHeader, relocationTableIndex, withAddend);
		int info = (int) getRelocationInfo();
		type = info & 0xFF;
		sectOffsetIndex = info >> 8 & 0xFF;
		relocateToIndex = info >> 16 & 0xFF;
	}

	@Override
	public int getSymbolIndex () {
		return 0; // TODO return offsetIndex?
	}

	@Override
	public long getOffset () {
		return super.getOffset();
	}

	@Override
	public int getType () {
		return type;
	}

	public int getSectOffsetIndex () {
		return sectOffsetIndex;
	}

	public int getRelocateToIndex () {
		return relocateToIndex;
	}

	@Override
	public DataType toDataType () {
		String dtName = "Elf32_Allegrex_Rel";
		Structure struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		struct.add(DWORD, "r_address", null);
		struct.add(BYTE, "r_type", null);
		struct.add(BYTE, "r_offsetIndex", null);
		struct.add(BYTE, "r_relocateToIndex", null);
		struct.add(BYTE, "r_unused", null);
		return struct;
	}
}
