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

import com.kotcrab.ghidra.allegrex.format.elf.PspElfConstants;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.Allegrex_ElfExtension;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class Allegrex_ElfRelocationHandler extends ElfRelocationHandler {
	// TODO support image base change
	//	private static final String GOT_SYMBOL_NAME = "_GLOBAL_OFFSET_TABLE_";
	private static final String GP_DISP_SYMBOL_NAME = "_gp_disp";
	private static final String GP_GNU_LOCAL_SYMBOL_NAME = "__gnu_local_gp";

	@Override
	public boolean canRelocate (ElfHeader elf) {
		return elf.e_machine() == PspElfConstants.INSTANCE.getEM_MIPS_PSP_HACK(); // check elf header flags
	}

	@Override
	public Allegrex_ElfRelocationContext createRelocationContext (ElfLoadHelper loadHelper,
																  ElfRelocationTable relocationTable,
																  Map<ElfSymbol, Address> symbolMap) {
		return new Allegrex_ElfRelocationContext(this, loadHelper, relocationTable, symbolMap);
	}

	@Override
	public void relocate (ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != PspElfConstants.INSTANCE.getEM_MIPS_PSP_HACK()) {
			return;
		}

		Allegrex_ElfRelocationContext mipsRelocationContext = (Allegrex_ElfRelocationContext) elfRelocationContext;

		int type = relocation.getType();
		int symbolIndex = relocation.getSymbolIndex();

		boolean saveValueForNextReloc = mipsRelocationContext.nextRelocationHasSameOffset(relocation);
//		doRelocate(mipsRelocationContext, type, symbolIndex, relocation, relocationAddress, saveValueForNextReloc);
		doAllegrexRelocation(mipsRelocationContext, relocation, relocationAddress);
	}

	private void doAllegrexRelocation (Allegrex_ElfRelocationContext context, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException {
		var program = context.getProgram();
		var memory = program.getMemory();
		var programHeaders = context.getElfHeader().getProgramHeaders();

		int info = (int) relocation.getRelocationInfo();
		var type = info & 0xFF;
		var sectOffsetIndex = info >> 8 & 0xFF;
		var relocateToIndex = info >> 16 & 0xFF;

		var offsetSect = (int) programHeaders[sectOffsetIndex].getVirtualAddress();
		var addr = relocationAddress.add(offsetSect);

		var relocateToSect = (int) program.getImageBase().add(programHeaders[relocateToIndex].getVirtualAddress()).getOffset();

		var currentValue = memory.getInt(addr);
		var newValue = 0;

		switch (type) {
			case Allegrex_ElfRelocationConstants.R_MIPS_16:
				newValue = relocate(currentValue, 0xFFFF, relocateToSect);
				break;
			case Allegrex_ElfRelocationConstants.R_MIPS_32:
				newValue = currentValue + relocateToSect;
				break;
			case Allegrex_ElfRelocationConstants.R_MIPS_26:
				newValue = relocate(currentValue, 0x3FFFFFF, relocateToSect >> 2);
				break;
			case Allegrex_ElfRelocationConstants.R_MIPS_HI16:
				context.deferMipsHi16Relocation(new Allegrex_DeferredRelocation(type, offsetSect, relocateToSect, addr, currentValue));
				break;
			case Allegrex_ElfRelocationConstants.R_MIPS_LO16:
				newValue = relocate(currentValue, 0xFFFF, relocateToSect);
				context.completeMipsHi16Relocations((short) (currentValue & 0xFFFF));
				break;
		}

		if (newValue != 0) {
			memory.setInt(addr, newValue);
		} else if(type != Allegrex_ElfRelocationConstants.R_MIPS_NONE) {
			// TODO mark uhnadled relocation
		}
	}

	private int relocate (int data, int mask, int relocateTo) {
		//    return (data and mask.inv()) or (((data and mask) + relocateTo) and mask)
		return (data & ~mask) | (((data & mask) + relocateTo) & mask);
	}

	/**
	 * Perform MIPS ELF relocation
	 * @param mipsRelocationContext MIPS ELF relocation context
	 * @param relocType relocation type (unpacked from relocation r_info)
	 * @param relocationAddress address at which relocation is applied (i.e., relocation offset)
	 * @param saveValue true if result value should be stored in mipsRelocationContext.savedAddend
	 * and mipsRelocationContext.useSavedAddend set true.  If false, result value should be written
	 * to relocationAddress per relocation type.
	 */
	private void doRelocate (Allegrex_ElfRelocationContext mipsRelocationContext, int relocType,
							 int symbolIndex, ElfRelocation relocation, Address relocationAddress, boolean saveValue)
			throws MemoryAccessException, NotFoundException, AddressOutOfBoundsException {

		if (relocType == Allegrex_ElfRelocationConstants.R_MIPS_NONE) {
			return;
		}

		Program program = mipsRelocationContext.getProgram();
		Memory memory = program.getMemory();
		MessageLog log = mipsRelocationContext.getLog();

		long offset = (int) relocationAddress.getOffset();

		ElfSymbol elfSymbol = mipsRelocationContext.getSymbol(symbolIndex);

		long symbolValue = mipsRelocationContext.getSymbolValue(elfSymbol);

		String symbolName = elfSymbol.getNameAsString();

		long addend = 0;
		if (mipsRelocationContext.useSavedAddend) {
			if (mipsRelocationContext.savedAddendHasError) {
				markAsError(program, relocationAddress, Integer.toString(relocType), symbolName,
						"Stacked relocation failure", log);
				mipsRelocationContext.useSavedAddend = saveValue;
				mipsRelocationContext.savedAddend = 0;
				return;
			}
			addend = mipsRelocationContext.savedAddend;
		} else if (relocation.hasAddend()) {
			addend = relocation.getAddend();
		}

		// Treat global GOT_PAGE relocations as GOT_DISP
		if (!elfSymbol.isLocal()) {
			if (relocType == Allegrex_ElfRelocationConstants.R_MIPS_GOT_PAGE) {
				relocType = Allegrex_ElfRelocationConstants.R_MIPS_GOT_DISP;
				addend = 0; // addend handled by GOT_OFST
			} else if (relocType == Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT_PAGE) {
				relocType = Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT_DISP;
				addend = 0; // addend handled by GOT_OFST
			}
		}

		mipsRelocationContext.useSavedAddend = saveValue;
		mipsRelocationContext.savedAddendHasError = false;
		mipsRelocationContext.savedAddend = 0;

		boolean isGpDisp = false;
		if (GP_DISP_SYMBOL_NAME.equals(symbolName)) {
			isGpDisp = true;
		} else if (GP_GNU_LOCAL_SYMBOL_NAME.equals(symbolName)) {
			// TODO: GP based relocation not yet supported - need to evaluate an example
			markAsError(program, relocationAddress, Integer.toString(relocType), symbolName,
					GP_GNU_LOCAL_SYMBOL_NAME + " relocation not yet supported", log);
			if (saveValue) {
				mipsRelocationContext.savedAddendHasError = true;
			}
			return;
		}

		int oldValue = unshuffle(memory.getInt(relocationAddress), relocType, mipsRelocationContext);
		int value = 0; // computed value which will be used as savedAddend if needed
		int newValue = 0; // value blended with oldValue as appropriate for relocation
		boolean writeNewValue = false;

		switch (relocType) {

			case Allegrex_ElfRelocationConstants.R_MIPS_GOT_OFST:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT_OFST:
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue & 0xffff;
				}

				long pageOffset = (symbolValue + addend + 0x8000) & ~0xffff;
				value = (int) (symbolValue + addend - pageOffset);

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_GOT_PAGE:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT_PAGE:

				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue & 0xffff;
				}

				pageOffset = ((symbolValue + addend + 0x8000) & ~0xffff);

				// Get section GOT entry for local symbol
				Address gotAddr = mipsRelocationContext.getSectionGotAddress(pageOffset);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), elfSymbol.getNameAsString(),
							"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
									elfSymbol.getNameAsString(),
							mipsRelocationContext.getLog());
					return;
				}

				value = (int) getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), symbolName,
							"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return;
				}

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_GOT_DISP:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT_DISP:
			case Allegrex_ElfRelocationConstants.R_MIPS_GOT_HI16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT_HI16:

				// Get section GOT entry for local symbol
				gotAddr = mipsRelocationContext.getSectionGotAddress(symbolValue);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), elfSymbol.getNameAsString(),
							"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
									elfSymbol.getNameAsString(),
							mipsRelocationContext.getLog());
					return;
				}

				// use address offset within section GOT as symbol value
				value = (int) getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), symbolName,
							"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return;
				}

				int appliedValue;
				if (relocType == Allegrex_ElfRelocationConstants.R_MIPS_GOT_DISP) {
					appliedValue = value & 0xffff;
				} else {
					appliedValue = ((value + 0x8000) >> 16) & 0xffff;
				}

				newValue = (oldValue & ~0xffff) | appliedValue;
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_GOT16:
			case Allegrex_ElfRelocationConstants.R_MIPS16_GOT16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT16:

				if (elfSymbol.isLocal()) {
					// Defer processing of local GOT16 relocations until suitable LO16 relocation is processed
					Allegrex_DeferredRelocationOld got16reloc = new Allegrex_DeferredRelocationOld(relocType,
							elfSymbol, relocationAddress, oldValue, (int) addend, isGpDisp);
					mipsRelocationContext.addGOT16Relocation(got16reloc);
					break;
				}

				// fall-through

			case Allegrex_ElfRelocationConstants.R_MIPS_CALL16:
			case Allegrex_ElfRelocationConstants.R_MIPS16_CALL16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_CALL16:

				// Get section GOT entry for local symbol
				gotAddr = mipsRelocationContext.getSectionGotAddress(symbolValue + addend);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), elfSymbol.getNameAsString(),
							"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
									elfSymbol.getNameAsString(),
							mipsRelocationContext.getLog());
					return;
				}

				value = (int) getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), symbolName,
							"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return;
				}

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_CALL_HI16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_CALL_HI16:

				// Get section GOT entry for local symbol
				gotAddr = mipsRelocationContext.getSectionGotAddress(symbolValue + addend);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), elfSymbol.getNameAsString(),
							"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
									elfSymbol.getNameAsString(),
							mipsRelocationContext.getLog());
					return;
				}

				value = (int) getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), symbolName,
							"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return;
				}

				newValue = (oldValue & ~0xffff) | (((value + 0x8000) >> 16) & 0xffff);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_HI16:
			case Allegrex_ElfRelocationConstants.R_MIPS16_HI16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_HI16:
				// Defer processing of HI16 relocations until suitable LO16 relocation is processed
				Allegrex_DeferredRelocationOld hi16reloc = new Allegrex_DeferredRelocationOld(relocType,
						elfSymbol, relocationAddress, oldValue, (int) addend, isGpDisp);
				mipsRelocationContext.addHI16Relocation(hi16reloc);
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_LO16:
			case Allegrex_ElfRelocationConstants.R_MIPS16_LO16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_LO16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_HI0_LO16:

				processHI16Relocations(mipsRelocationContext, relocType, elfSymbol, (int) addend);

				processGOT16Relocations(mipsRelocationContext, relocType, elfSymbol, (int) addend);

				if (isGpDisp) {
					value = (int) mipsRelocationContext.getGPValue();
					if (value == -1) {
						markAsError(program, relocationAddress, Integer.toString(relocType),
								symbolName, "Failed to perform GP-based relocation",
								mipsRelocationContext.getLog());
						if (saveValue) {
							mipsRelocationContext.savedAddendHasError = true;
						}
						return;
					}
					if (relocType == Allegrex_ElfRelocationConstants.R_MIPS16_LO16) {
						value -= (offset & ~0x3);
					} else {
						value -= offset - 4;
					}
				} else {
					value = (int) symbolValue;
				}
				value += mipsRelocationContext.extractAddend() ? (oldValue & 0xffff) : addend;

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_32:
				value = (int) symbolValue;
				value += mipsRelocationContext.extractAddend() ? oldValue : addend;

				newValue = value;
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_REL32:
				// TODO: some guess-work was used here
				if (symbolIndex == 0) {
					// TODO: may need to use relocation section load address if applicable
					symbolValue = program.getImageBase().getOffset();
				}
				value = (int) symbolValue;
				value += mipsRelocationContext.extractAddend() ? oldValue : addend;

				newValue = value;
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_26:
			case Allegrex_ElfRelocationConstants.R_MIPS16_26:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_26_S1:
				int shift = (relocType == Allegrex_ElfRelocationConstants.R_MICROMIPS_26_S1) ? 1 : 2;
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue;
					addend &= Allegrex_ElfRelocationConstants.MIPS_LOW26;
					addend <<= shift;
				}
				// TODO: cross-mode jump detection/handling is unsupported
				if (elfSymbol.isLocal()) {
					value = (int) ((addend |
							((offset + 4) & (0xfc000000 << shift)) + symbolValue) >> shift);
				} else {
					value = (signExtend((int) addend, 26 + shift) + (int) symbolValue) >> shift;
				}
				value &= Allegrex_ElfRelocationConstants.MIPS_LOW26;

				newValue = (oldValue & ~Allegrex_ElfRelocationConstants.MIPS_LOW26) | value;
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_PC16:
				newValue =
						mipsRelocationContext.extractAddend() ? (oldValue & 0xffff) << 2 : (int) addend;
				long newValueBig = signExtend(newValue, 18);
				newValueBig += symbolValue - offset;

				value = (int) newValueBig;
				newValue = (oldValue & ~0xffff) | ((int) (newValueBig >> 2) & 0xffff);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_64:
				if (mipsRelocationContext.extractAddend()) {
					addend = memory.getLong(relocationAddress);
				}
				// NOTE: provisions may be needed for sign-extending a 32-bit value
				newValueBig = symbolValue + addend;
				if (saveValue) {
					mipsRelocationContext.savedAddend = newValueBig;
				} else {
					memory.setLong(relocationAddress, newValueBig);
				}
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_HIGHER:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_HIGHER:
				newValueBig = (mipsRelocationContext.extractAddend() ? oldValue : addend) & 0xffff;
				newValueBig += symbolValue + 0x080008000L;
				value = (int) ((newValueBig >> 32) & 0xffff);

				newValue = (oldValue & ~0xffff) | value;
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_HIGHEST:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_HIGHEST:
				newValueBig = (mipsRelocationContext.extractAddend() ? oldValue : addend) & 0xffff;
				newValueBig += symbolValue + 0x0800080008000L;
				value = (int) ((newValueBig >> 48) & 0xffff);

				newValue = (oldValue & ~0xffff) | value;
				writeNewValue = true;
				break;

//			case MIPS_ElfRelocationConstants.R_MIPS_TLS_TPREL32:
//				if (mipsRelocationContext.extractAddend()) {
//					addend = oldValue;
//				}
//				value = (int) ((symbolValue + addend) - TP_OFFSET);
//
//				newValue = value;
//				writeNewValue = true;
//				break;
//
//			case MIPS_ElfRelocationConstants.R_MIPS_TLS_TPREL64:
//				if (mipsRelocationContext.extractAddend()) {
//					addend = oldValue;
//				}
//				newValueBig = symbolValue + addend - TP_OFFSET;
//
//				if (saveValue) {
//					mipsRelocationContext.savedAddend = newValueBig;
//				}
//				else {
//					memory.setLong(relocationAddress, newValueBig);
//				}
//				break;
//
//			case MIPS_ElfRelocationConstants.R_MIPS_TLS_DTPREL32:
//				if (mipsRelocationContext.extractAddend()) {
//					addend = oldValue;
//				}
//				value = (int) ((symbolValue + addend) - DTP_OFFSET);
//
//				newValue = value;
//				writeNewValue = true;
//				break;
//
//
//			case MIPS_ElfRelocationConstants.R_MIPS_TLS_DTPREL64:
//				if (mipsRelocationContext.extractAddend()) {
//					addend = oldValue;
//				}
//				newValueBig = symbolValue + addend - DTP_OFFSET;
//
//				if (saveValue) {
//					mipsRelocationContext.savedAddend = newValueBig;
//				}
//				else {
//					memory.setLong(relocationAddress, newValueBig);
//				}
//				break;

			case Allegrex_ElfRelocationConstants.R_MICROMIPS_PC7_S1:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0x7f0000) >> 15;
				}
				value = (int) (((symbolValue + addend) - offset) >> 1) & 0x7f;

				newValue = (oldValue & ~0x7f0000) | (value << 16);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MICROMIPS_PC10_S1:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0x3ff0000) >> 15;
				}
				value = (int) (((symbolValue + addend) - offset) >> 1) & 0x3ff;

				newValue = (oldValue & ~0x3ff0000) | (value << 16);
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MICROMIPS_PC16_S1:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0xffff) << 1;
				}
				value = (int) (((symbolValue + addend) - offset) >> 1) & 0xffff;

				newValue = (oldValue & ~0xffff) | value;
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_GPREL16:
			case Allegrex_ElfRelocationConstants.R_MIPS16_GPREL:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GPREL16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GPREL7_S2:
			case Allegrex_ElfRelocationConstants.R_MIPS_LITERAL:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_LITERAL:
				if (mipsRelocationContext.extractAddend()) {
					if (relocType == Allegrex_ElfRelocationConstants.R_MICROMIPS_GPREL7_S2) {
						addend = (oldValue & 0x7f0000) >> 14;
					} else {
						addend = oldValue & 0xffff;
					}
					addend = signExtend((int) addend, 16);
				}

				long gp = mipsRelocationContext.getGPValue();
				if (gp == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), symbolName,
							"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return;
				}

				if (elfSymbol.isSection()) {
					// TODO: this computation has been completely fudged to get the desired results.
					// It is unclear why the addend is not needed or the 0x10 factor.  This could
					// be specific to the test sample and may break for others.  This may reflect
					// the offset from the start of the function which could easily vary and may break.
					value = (int) (offset - gp - 0x10); // value appears to be functionStart (t9) - gp, but we don't know where the function start is
				} else {
					value = (int) (symbolValue + addend - gp);
				}

				// TODO: unsure if local symbol needs additional gp adjustment
				if (relocType == Allegrex_ElfRelocationConstants.R_MICROMIPS_GPREL7_S2) {
					newValue = (oldValue & ~0x7f0000) | ((value & 0x7f) << 16);
				} else {
					newValue = (oldValue & ~0xffff) | (value & 0xffff);
				}
				writeNewValue = true;
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_SUB:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_SUB:
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue;
				}
				newValueBig = symbolValue - addend;

				if (saveValue) {
					mipsRelocationContext.savedAddend = newValueBig;
				} else {
					memory.setLong(relocationAddress, newValueBig);
				}
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_COPY:
				// TODO: Requires symbol lookup into dynamic library - not sure what we can do here
				markAsWarning(program, relocationAddress, "R_MIPS_COPY", symbolName, symbolIndex,
						"Runtime copy not supported", log);
				if (saveValue) {
					mipsRelocationContext.savedAddendHasError = true;
				}
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_JUMP_SLOT:
				if (saveValue) {
					mipsRelocationContext.savedAddend = symbolValue;
				} else if (mipsRelocationContext.getElfHeader().is64Bit()) {
					memory.setLong(relocationAddress, symbolValue);
				} else {
					memory.setInt(relocationAddress, (int) symbolValue);
				}
				break;

			case Allegrex_ElfRelocationConstants.R_MIPS_JALR:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_JALR:

				boolean success = false;
				Address symAddr = mipsRelocationContext.getSymbolAddress(elfSymbol);
				if (symAddr != null) {
					MemoryBlock block = memory.getBlock(symAddr);
					if (block != null) {
						if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName())) {

							success =
									mipsRelocationContext.getLoadHelper().createExternalFunctionLinkage(
											symbolName, symAddr, null) != null;

							if (success) {
								// Inject appropriate JAL instruction
								if (relocType == Allegrex_ElfRelocationConstants.R_MICROMIPS_JALR) {
									int offsetBits = (int) (symAddr.getOffset() >> 1) & 0x3ffffff;
									// TODO: upper bits should really come from delay slot
									int microJalrBits = 0xf4000000 | offsetBits;
									memory.setShort(relocationAddress,
											(short) (microJalrBits >>> 16));
									memory.setShort(relocationAddress.add(2),
											(short) microJalrBits);
								} else {
									int offsetBits = (int) (symAddr.getOffset() >> 2) & 0x3ffffff;
									// TODO: upper bits should really come from delay slot
									int jalrBits = 0x0c000000 | offsetBits;
									memory.setInt(relocationAddress, jalrBits);
								}
							}
						} else {
							// assume OK for internal function linkage
							success = true; // do nothing
						}
					}
				}
				if (!success) {
					markAsError(program, relocationAddress,
							relocType == Allegrex_ElfRelocationConstants.R_MIPS_JALR ? "R_MIPS_JALR"
									: "R_MICROMIPS_JALR",
							symbolName, "Failed to establish external linkage", log);
				}
				break;

			default:
				markAsUnhandled(program, relocationAddress, relocType, symbolIndex,
						elfSymbol.getNameAsString(), log);
				if (saveValue) {
					mipsRelocationContext.savedAddendHasError = true;
				}
				break;
		}

		if (writeNewValue) {
			if (saveValue) {
				// Save "value" as addend for next relocation
				mipsRelocationContext.savedAddend = value;
			} else {
				// Write 32-bit memory location at relocationAddress using "newValue".
				// Each relocation which sets writeNewValue must establish a 32-bit newValue
				// to be written to relocationAddress.
				memory.setInt(relocationAddress,
						shuffle(newValue, relocType, mipsRelocationContext));
			}
		}

	}

	private boolean isMIPS16Reloc (int type) {
		return type >= Allegrex_ElfRelocationConstants.R_MIPS16_LO &&
				type <= Allegrex_ElfRelocationConstants.R_MIPS16_HI;
	}

	private boolean isMicroMIPSReloc (int type) {
		return type >= Allegrex_ElfRelocationConstants.R_MICROMIPS_LO &&
				type <= Allegrex_ElfRelocationConstants.R_MICROMIPS_HI;
	}

	private boolean shuffleRequired (int type) {
		return isMIPS16Reloc(type) ||
				(isMicroMIPSReloc(type) && type != Allegrex_ElfRelocationConstants.R_MICROMIPS_PC7_S1 &&
						type != Allegrex_ElfRelocationConstants.R_MICROMIPS_PC10_S1);
	}

	private boolean isMIPS16_26_JAL_Reloc (int type, ElfRelocationContext elfRelocationContext) {
		return (type == Allegrex_ElfRelocationConstants.R_MIPS16_26 &&
				elfRelocationContext.getElfHeader().isRelocatable());
	}

	private int unshuffle (int value, int type, ElfRelocationContext elfRelocationContext) {
		if (!shuffleRequired(type)) {
			return value;
		}

		int first;
		int second;
		if (elfRelocationContext.isBigEndian()) {
			first = value >>> 16;
			second = value & 0xffff;
		} else {
			first = value & 0xffff;
			second = value >>> 16;
		}

		if (isMIPS16_26_JAL_Reloc(type, elfRelocationContext)) {
			value = (((first & 0xf800) << 16) | ((second & 0xffe0) << 11) | ((first & 0x1f) << 11) |
					(first & 0x7e0) | (second & 0x1f));
		} else if (isMicroMIPSReloc(type) || type == Allegrex_ElfRelocationConstants.R_MIPS16_26) {
			value = first << 16 | second;
		} else {
			value = (((first & 0xfc00) << 16) | ((first & 0x3e0) << 11) | ((first & 0x1f) << 21) |
					second);
		}
		return value;
	}

	private int shuffle (int value, int type, ElfRelocationContext elfRelocationContext) {
		if (!shuffleRequired(type)) {
			return value;
		}

		short first;
		short second;
		if (isMIPS16_26_JAL_Reloc(type, elfRelocationContext)) {
			first = (short) (((value >> 16) & 0xf800) | ((value >> 11) & 0x1f) | (value & 0x7e0));
			second = (short) (((value >> 11) & 0xffe0) | (value & 0x1f));
		} else if (isMicroMIPSReloc(type) || type == Allegrex_ElfRelocationConstants.R_MIPS16_26) {
			first = (short) (value >> 16);
			second = (short) value;
		} else {
			first = (short) (((value >> 16) & 0xfc00) | ((value >> 11) & 0x3e0) |
					((value >> 21) & 0x1f));
			second = (short) value;
		}

		if (elfRelocationContext.isBigEndian()) {
			value = (first << 16) | (second & 0xffff);
		} else {
			value = (second << 16) | (first & 0xffff);
		}

		return value;
	}

	private boolean matchingHiLo16Types (int hi16Type, int lo16Type) {
		switch (hi16Type) {
			case Allegrex_ElfRelocationConstants.R_MIPS_HI16:
			case Allegrex_ElfRelocationConstants.R_MIPS_GOT16:
				return lo16Type == Allegrex_ElfRelocationConstants.R_MIPS_LO16;
			case Allegrex_ElfRelocationConstants.R_MIPS16_HI16:
			case Allegrex_ElfRelocationConstants.R_MIPS16_GOT16:
				return lo16Type == Allegrex_ElfRelocationConstants.R_MIPS16_LO16;
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_HI16:
			case Allegrex_ElfRelocationConstants.R_MICROMIPS_GOT16:
				return lo16Type == Allegrex_ElfRelocationConstants.R_MICROMIPS_LO16;
		}
		return false;
	}

	private int signExtend (int val, int bits) {
		int shift = 32 - bits;
		return (val << shift) >> shift;
	}

	/**
	 * Processes all pending HI16 relocations which match with the specified LO16 relocation
	 */
	private void processHI16Relocations (Allegrex_ElfRelocationContext mipsRelocationContext,
										 int lo16RelocType, ElfSymbol lo16ElfSymbol, int lo16Addend) {

		Iterator<Allegrex_DeferredRelocationOld> iterateHi16 = mipsRelocationContext.iterateHi16();
		while (iterateHi16.hasNext()) {
			Allegrex_DeferredRelocationOld hi16reloc = iterateHi16.next();
			if (matchingHiLo16Types(hi16reloc.relocType, lo16RelocType) &&
					hi16reloc.elfSymbol == lo16ElfSymbol) {
				processHI16Relocation(mipsRelocationContext, hi16reloc, lo16Addend);
				iterateHi16.remove(); // remove queued HI16 relocation if processed
			}
		}
	}

	/**
	 * Complete HI16 relocation (R_MIPS_HI16, R_MIPS16_HI16, R_MICROMIPS_HI16) using
	 * specified LO16 relocation data
	 * @return true if successful or false if unsupported
	 */
	private void processHI16Relocation (Allegrex_ElfRelocationContext mipsRelocationContext,
										Allegrex_DeferredRelocationOld hi16reloc, int lo16Addend) {

		int newValue;
		if (hi16reloc.isGpDisp) {

			newValue = (int) mipsRelocationContext.getGPValue();
			if (newValue == -1) {
				markAsError(mipsRelocationContext.getProgram(), hi16reloc.relocAddr,
						Integer.toString(hi16reloc.relocType), hi16reloc.elfSymbol.getNameAsString(),
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
				return;
			}
			if (hi16reloc.relocType == Allegrex_ElfRelocationConstants.R_MIPS16_HI16) {
				newValue -= (hi16reloc.relocAddr.getOffset() + 4) & ~0x3;
			} else {
				newValue -= hi16reloc.relocAddr.getOffset();
			}
		} else {
			newValue = (int) mipsRelocationContext.getSymbolValue(hi16reloc.elfSymbol);
		}
// FIXME: should always use hi16reloc.addend - figure out at time of deferral
		int addend;
		if (mipsRelocationContext.extractAddend()) {
			addend = ((hi16reloc.oldValue & 0xffff) << 16) + lo16Addend;
		} else {
			addend = hi16reloc.addend;
		}

		newValue = (newValue + addend + 0x8000) >> 16;
		newValue = (hi16reloc.oldValue & ~0xffff) | (newValue & 0xffff);
		Memory memory = mipsRelocationContext.getProgram().getMemory();
		try {
			memory.setInt(hi16reloc.relocAddr,
					shuffle(newValue, hi16reloc.relocType, mipsRelocationContext));
		} catch (MemoryAccessException e) {
			// Unexpected since we did a previous getInt without failure
			throw new AssertException(e);
		}
	}

	/**
	 * Processes all pending GOT16 relocations which match with the specified LO16 relocation
	 */
	private void processGOT16Relocations (Allegrex_ElfRelocationContext mipsRelocationContext,
										  int lo16RelocType, ElfSymbol lo16ElfSymbol, int lo16Addend) {

		Iterator<Allegrex_DeferredRelocationOld> iterateGot16 = mipsRelocationContext.iterateGot16();
		while (iterateGot16.hasNext()) {
			Allegrex_DeferredRelocationOld hi16reloc = iterateGot16.next();
			if (matchingHiLo16Types(hi16reloc.relocType, lo16RelocType) &&
					hi16reloc.elfSymbol == lo16ElfSymbol) {
				processGOT16Relocation(mipsRelocationContext, hi16reloc, lo16Addend);
				iterateGot16.remove(); // remove queued GOT16 relocation if processed
			}
		}
	}

	/**
	 * Complete Local GOT16 relocation (R_MIPS_GOT16, R_MIPS16_GOT16, R_MICROMIPS_GOT16) using
	 * specified LO16 relocation data.  Section GOT entry will be utilized.
	 * @return true if successful or false if unsupported
	 */
	private void processGOT16Relocation (Allegrex_ElfRelocationContext mipsRelocationContext,
										 Allegrex_DeferredRelocationOld got16reloc, int lo16Addend) {

		long addend;
		if (mipsRelocationContext.extractAddend()) {
			addend = ((got16reloc.oldValue & 0xffff) << 16) + lo16Addend;
		} else {
			addend = got16reloc.addend;
		}

		long symbolValue = (int) mipsRelocationContext.getSymbolValue(got16reloc.elfSymbol);
		String symbolName = got16reloc.elfSymbol.getNameAsString();

		long value = (symbolValue + addend + 0x8000) & ~0xffff; // generate page offset

		// Get section GOT entry for local symbol
		Address gotAddr = mipsRelocationContext.getSectionGotAddress(value);
		if (gotAddr == null) {
			// failed to allocate section GOT entry for symbol
			markAsError(mipsRelocationContext.getProgram(), got16reloc.relocAddr,
					Integer.toString(got16reloc.relocType), symbolName,
					"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
							symbolName,
					mipsRelocationContext.getLog());
			return;
		}

		// use address offset within section GOT as value
		value = getGpOffset(mipsRelocationContext, gotAddr.getOffset());
		if (value == -1) {
			// Unhandled GOT/GP case
			markAsError(mipsRelocationContext.getProgram(), got16reloc.relocAddr,
					Integer.toString(got16reloc.relocType), symbolName,
					"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
			return;
		}

		int newValue = (got16reloc.oldValue & ~0xffff) | ((int) value & 0xffff);

		Memory memory = mipsRelocationContext.getProgram().getMemory();
		try {
			memory.setInt(got16reloc.relocAddr,
					shuffle(newValue, got16reloc.relocType, mipsRelocationContext));
		} catch (MemoryAccessException e) {
			// Unexpected since we did a previous getInt without failure
			throw new AssertException(e);
		}
	}

	private long getGpOffset (Allegrex_ElfRelocationContext mipsRelocationContext, long value) {
		// TODO: this is a simplified use of GP and could be incorrect when multiple GPs exist
		long gp = mipsRelocationContext.getGPValue();
		if (gp == -1) {
			return -1;
		}

		return value - gp;
	}

	/**
	 * <code>Allegrex_ElfRelocationContext</code> provides extended relocation context with the ability
	 * to retain deferred relocation lists.  In addition, the ability to generate a section GOT
	 * table is provided to facilitate relocations encountered within object modules.
	 */
	private static class Allegrex_ElfRelocationContext extends ElfRelocationContext {

		private LinkedList<Allegrex_DeferredRelocationOld> hi16list = new LinkedList<>();
		private LinkedList<Allegrex_DeferredRelocationOld> got16list = new LinkedList<>();

		private AddressRange sectionGotLimits;
		private Address sectionGotAddress;
		private Address lastSectionGotEntryAddress;
		private Address nextSectionGotEntryAddress;

		private Map<Long, Address> gotMap;

		private boolean useSavedAddend = false;
		private boolean savedAddendHasError = false;
		private long savedAddend;

		private ArrayList<Allegrex_DeferredRelocation> deferredMipsHi16Relocations = new ArrayList<>();

		Allegrex_ElfRelocationContext (Allegrex_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
									   ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
			super(handler, loadHelper, relocationTable, symbolMap);
		}

		public void deferMipsHi16Relocation (Allegrex_DeferredRelocation reloc) {
			deferredMipsHi16Relocations.add(reloc);
		}

		public void completeMipsHi16Relocations (short lo) throws MemoryAccessException {
			for (Allegrex_DeferredRelocation reloc : deferredMipsHi16Relocations) {
				int newAddr = reloc.oldValue << 16;
				newAddr += lo;
				newAddr += reloc.relocToSect;
				short newLo = (short) (newAddr & 0xFFFF);
				int newHi = (newAddr - newLo) >> 16;
				int newData = (reloc.oldValue & 0xFFFF0000) | newHi;
				program.getMemory().setInt(reloc.relocAddr, newData);
			}
			deferredMipsHi16Relocations.clear();
		}

		// TODO: move section GOT creation into ElfRelocationContext to make it
		// available to other relocation handlers

		private void allocateSectionGot () {
			int alignment = getLoadAdapter().getLinkageBlockAlignment();
			sectionGotLimits =
					getLoadHelper().allocateLinkageBlock(alignment, 0x10000, getSectionGotName());
			sectionGotAddress =
					sectionGotLimits != null ? sectionGotLimits.getMinAddress() : Address.NO_ADDRESS;
			nextSectionGotEntryAddress = sectionGotAddress;
			if (sectionGotLimits == null) {
				loadHelper.log("Failed to allocate " + getSectionGotName() +
						" block required for relocation processing");
			} else {
				loadHelper.log("Created " + getSectionGotName() +
						" block required for relocation processing (gp=0x" +
						Long.toHexString(getGPValue()) + ")");
			}
		}

		/**
		 * Allocate the next section GOT entry location.
		 * @return Address of GOT entry or null if unable to allocate.
		 */
		private Address getNextSectionGotEntryAddress () {
			if (nextSectionGotEntryAddress == null) {
				allocateSectionGot();
			}
			Address addr = nextSectionGotEntryAddress;
			if (addr != Address.NO_ADDRESS) {
				try {
					int pointerSize = loadHelper.getProgram().getDefaultPointerSize();
					Address lastAddr = nextSectionGotEntryAddress.addNoWrap(pointerSize - 1);
					if (sectionGotLimits.contains(lastAddr)) {
						lastSectionGotEntryAddress = lastAddr;
						nextSectionGotEntryAddress = lastSectionGotEntryAddress.addNoWrap(1);
						if (!sectionGotLimits.contains(nextSectionGotEntryAddress)) {
							nextSectionGotEntryAddress = Address.NO_ADDRESS;
						}
					} else {
						// unable to allocation entry size
						nextSectionGotEntryAddress = Address.NO_ADDRESS;
						return Address.NO_ADDRESS;
					}
				} catch (AddressOverflowException e) {
					nextSectionGotEntryAddress = Address.NO_ADDRESS;
				}
			}
			return addr != Address.NO_ADDRESS ? addr : null;
		}

		/**
		 * Get the preferred GP.
		 * NOTE: This needs work to properly handle the use of multiple GP's
		 * @return preferred GP value or -1 if unable to determine GP
		 */
		public long getGPValue () {

			// TODO: 64-bit should really use .MIPS.options REGINFO.ri_gp_value in some capacity

			long gp = getAdjustedGPValue();
			if (gp == -1) {

				// TODO: we should probably not resort to assuming use of fabricated got so easily
				// since getAdjustedGPValue has rather limited capability at present

				// assume GP relative to fabricated GOT
				if (sectionGotAddress == null) {
					allocateSectionGot();
				}
				if (sectionGotAddress == Address.NO_ADDRESS) {
					return -1;
				}
				// gp if defined as 0x7ff0 byte offset into the global offset table
				return sectionGotAddress.getOffset() + 0x7ff0;
			}

			return gp;
		}

		@Override
		public boolean extractAddend () {
			return !relocationTable.hasAddendRelocations() && !useSavedAddend;
		}

		/**
		 * Determine if the next relocation has the same offset.
		 * If true, the computed value should be stored to savedAddend and
		 * useSaveAddend set true.
		 * //		 * @param relocIndex current relocation index
		 * @return true if next relocation has same offset
		 */
		boolean nextRelocationHasSameOffset (ElfRelocation relocation) {
			ElfRelocation[] relocations = relocationTable.getRelocations();
			int relocIndex = relocation.getRelocationIndex();
			if (relocIndex < 0 || relocIndex >= (relocations.length - 1)) {
				return false;
			}
			return relocations[relocIndex].getOffset() == relocations[relocIndex + 1].getOffset() &&
					relocations[relocIndex + 1].getType() != Allegrex_ElfRelocationConstants.R_MIPS_NONE;
		}

		/**
		 * Get or allocate a GOT entry for the specified symbolValue
		 * @return GOT entry address or null if unable to allocate
		 */
		public Address getSectionGotAddress (long symbolValue) {
			Address addr = null;
			if (gotMap == null) {
				gotMap = new HashMap<>();
			} else {
				addr = gotMap.get(symbolValue);
			}
			if (addr == null) {
				addr = getNextSectionGotEntryAddress();
				if (addr == null) {
					return null;
				}
				gotMap.put(symbolValue, addr);
			}
			return addr;
		}

		private String getSectionGotName () {
			String sectionName = relocationTable.getSectionToBeRelocated().getNameAsString();
			return "%got" + sectionName;
		}

		/**
		 * Flush the section GOT table to a new %got memory block
		 */
		private void createGot () {
			if (lastSectionGotEntryAddress == null) {
				return;
			}
			MemoryBlockUtil mbu = loadHelper.getMemoryBlockUtil();
			int size = (int) lastSectionGotEntryAddress.subtract(sectionGotAddress) + 1;
			String sectionName = relocationTable.getSectionToBeRelocated().getNameAsString();
			String blockName = getSectionGotName();
			try {
				MemoryBlock block = mbu.createInitializedBlock(blockName, sectionGotAddress, null,
						size, "GOT for " + sectionName + " section", "MIPS-Elf Loader", true, false,
						false, TaskMonitor.DUMMY);
				DataConverter converter =
						program.getMemory().isBigEndian() ? BigEndianDataConverter.INSTANCE
								: LittleEndianDataConverter.INSTANCE;
				for (long symbolValue : gotMap.keySet()) {
					Address addr = gotMap.get(symbolValue);
					byte[] bytes;
					if (program.getDefaultPointerSize() == 4) {
						bytes = converter.getBytes((int) symbolValue);
					} else {
						bytes = converter.getBytes(symbolValue);
					}
					block.putBytes(addr, bytes);
					loadHelper.createData(addr, PointerDataType.dataType);
				}
			} catch (AddressOverflowException | MemoryAccessException e) {
				throw new AssertException(e); // unexpected
			}
		}

		/**
		 * Get the GP value
		 * @return adjusted GP value or -1 if _mips_gp_value symbol not defined.
		 */
		long getAdjustedGPValue (/* reloc_object */) {

			// TODO: should we try using reginfo and gp_value information if needed

			// TODO: this is a simplified use of GP and could be incorrect when multiple GPs exist

			Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program,
					Allegrex_ElfExtension.MIPS_GP_VALUE_SYMBOL, err -> getLog().error("MIPS_ELF", err));
			if (symbol == null) {
				return -1;
			}
			return symbol.getAddress().getOffset();
		}

		@Override
		public long getSymbolValue (ElfSymbol symbol) {
			if ("__gnu_local_gp".equals(symbol.getNameAsString())) {
				return getAdjustedGPValue(); // TODO: need to verify this case still
			}
			return super.getSymbolValue(symbol);
		}

		/**
		 * Iterate over deferred HI16 relocations.  Iterator may be used to remove
		 * entries as they are processed.
		 * @return HI16 relocation iterator
		 */
		Iterator<Allegrex_DeferredRelocationOld> iterateHi16 () {
			return hi16list.iterator();
		}

		/**
		 * Add HI16 relocation for deferred processing
		 * @param hi16reloc HI16 relocation
		 */
		void addHI16Relocation (Allegrex_DeferredRelocationOld hi16reloc) {
			hi16list.add(hi16reloc);
		}

		/**
		 * Iterate over deferred GOT16 relocations.  Iterator may be used to remove
		 * entries as they are processed.
		 * @return GOT16 relocation iterator
		 */
		Iterator<Allegrex_DeferredRelocationOld> iterateGot16 () {
			return got16list.iterator();
		}

		/**
		 * Add HI16 relocation for deferred processing
		 * //		 * @param hi16reloc HI16 relocation
		 */
		void addGOT16Relocation (Allegrex_DeferredRelocationOld got16reloc) {
			got16list.add(got16reloc);
		}

		@Override
		public void dispose () {
			for (Allegrex_DeferredRelocation reloc : deferredMipsHi16Relocations) {
				reloc.markUnprocessed(this, "LO16 Relocation (Allegrex)");
			}

			// Mark all deferred relocations which were never processed
			for (Allegrex_DeferredRelocationOld reloc : hi16list) {
				reloc.markUnprocessed(this, "LO16 Relocation");
			}
			hi16list.clear();
			for (Allegrex_DeferredRelocationOld reloc : got16list) {
				reloc.markUnprocessed(this, "LO16 Relocation");
			}
			got16list.clear();

			// Generate the section GOT table if required
			createGot();

			super.dispose();
		}
	}

	private static class Allegrex_DeferredRelocation {
		final int relocType;
		final int offsetSect;
		final int relocToSect;
		final Address relocAddr;
		final int oldValue;

		Allegrex_DeferredRelocation (int relocType, int offsetSect, int relocToSect, Address relocAddr, int oldValue) {
			this.relocType = relocType;
			this.offsetSect = offsetSect;
			this.relocToSect = relocToSect;
			this.relocAddr = relocAddr;
			this.oldValue = oldValue;
		}

		void markUnprocessed (Allegrex_ElfRelocationContext mipsRelocationContext, String missingDependencyName) {
			markAsError(mipsRelocationContext.getProgram(), relocAddr, Integer.toString(relocType),
					"", "Relocation missing required " + missingDependencyName,
					mipsRelocationContext.getLog());
		}
	}

	/**
	 * <code>Allegrex_DeferredRelocationOld</code> is used to capture a relocation whose processing
	 * must be deferred.
	 */
	private static class Allegrex_DeferredRelocationOld {

		final int relocType;
		final ElfSymbol elfSymbol;
		final Address relocAddr;
		final int oldValue;
		final int addend;
		final boolean isGpDisp;

		Allegrex_DeferredRelocationOld (int relocType, ElfSymbol elfSymbol, Address relocAddr, int oldValue,
										int addend, boolean isGpDisp) {
			this.relocType = relocType;
			this.elfSymbol = elfSymbol;
			this.relocAddr = relocAddr;
			this.oldValue = oldValue;
			this.addend = addend;
			this.isGpDisp = isGpDisp;
		}

		void markUnprocessed (Allegrex_ElfRelocationContext mipsRelocationContext,
							  String missingDependencyName) {
			markAsError(mipsRelocationContext.getProgram(), relocAddr, Integer.toString(relocType),
					elfSymbol.getNameAsString(), "Relocation missing required " + missingDependencyName,
					mipsRelocationContext.getLog());
		}
	}
}
