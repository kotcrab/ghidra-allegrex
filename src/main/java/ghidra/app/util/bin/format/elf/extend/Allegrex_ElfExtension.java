package ghidra.app.util.bin.format.elf.extend;

import allegrex.format.elf.relocation.AuxRelocationProcessor;
import ghidra.app.util.bin.format.elf.ElfDefaultGotPltMarkup;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderType;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderType;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.bin.format.elf.PspElfConstants;
import ghidra.app.util.bin.format.elf.PspElfHeader;
import ghidra.app.util.bin.format.elf.relocation.AllegrexElfRelocationExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.atomic.AtomicBoolean;

@SuppressWarnings("unused")
// Note that this class is derived from the MIPS_ElfExtension. When the comment
// says "PSP relocation section are not supported" it refers to the built-in
// MIPS plugin, not the Allegrex one.
public class Allegrex_ElfExtension extends ElfExtension {

  private static final String MIPS_STUBS_SECTION_NAME = ".MIPS.stubs";

  // GP value reflected by symbol address
  public static final String MIPS_GP_DISP_SYMBOL_NAME = "_gp_disp"; // relocation GP marker symbol
  public static final String MIPS_GP_GNU_LOCAL_SYMBOL_NAME = "__gnu_local_gp";
  public static final String MIPS_GP_VALUE_SYMBOL = "_mips_gp_value";
  public static final String MIPS_GP0_VALUE_SYMBOL = "_mips_gp0_value";

  // Elf Header - File Type
  public static final short ET_MIPS_PSP_PRX = (short) 0xffa0;

  // Elf Program Header Extensions
  public static final ElfProgramHeaderType PT_MIPS_REGINFO = new ElfProgramHeaderType(0x70000000,
    "PT_MIPS_REGINFO", "Register usage information.  Identifies one .reginfo section");
  public static final ElfProgramHeaderType PT_MIPS_OPTIONS =
    new ElfProgramHeaderType(0x70000002, "PT_MIPS_OPTIONS", ".MIPS.options section");

  // PT_MIPS_PSPREL1 relocation format not supported (does not link to symbol table):
  //  type = r_info & 0xf, readwrite = (r_info >> 8) & 0xff, relative = (r_info >> 16) & 0xff
  // Uses Elf32_Rel but relocation processing differs from standard MIPS relocation handler
  // see https://github.com/hrydgard/ppsspp/blob/master/Core/ELF/ElfReader.cpp
  public static final ElfProgramHeaderType PT_MIPS_PSPREL1 =
    new ElfProgramHeaderType(0x700000a0, "PT_MIPS_PSPREL1", "PSP relocation table");

  // PT_MIPS_PSPREL2 relocation format not supported (does not link to symbol table, non-standard format):
  // see https://github.com/hrydgard/ppsspp/blob/master/Core/ELF/ElfReader.cpp
  public static final ElfProgramHeaderType PT_MIPS_PSPREL2 =
    new ElfProgramHeaderType(0x700000a1, "PT_MIPS_PSPREL2", "PSP relocation table");

  // Elf Section Header Extensions
  public static final ElfSectionHeaderType SHT_MIPS_REGINFO = new ElfSectionHeaderType(0x70000006,
    "SHT_MIPS_REGINFO", "Section contains register usage information");
  public static final ElfSectionHeaderType SHT_MIPS_OPTIONS = new ElfSectionHeaderType(0x7000000d,
    "SHT_MIPS_OPTIONS", "Section contains miscellaneous options");

  // SHT_MIPS_PSPREL relocation format not supported (does not link to symbol table, uses Elf32_Rel):
  //   type = r_info & 0xf, readwrite = (r_info >> 8) & 0xff, relative = (r_info >> 16) & 0xff
  // see https://github.com/hrydgard/ppsspp/blob/master/Core/ELF/ElfReader.cpp
  public static final ElfSectionHeaderType SHT_MIPS_PSPREL =
    new ElfSectionHeaderType(0x700000a0, "SHT_MIPS_PSPREL", "PSP relocation table"); // relocations not supported

  // Elf Dynamic Type Extensions
  public static final ElfDynamicType DT_MIPS_LOCAL_GOTNO =
    new ElfDynamicType(0x7000000a, "DT_MIPS_LOCAL_GOTNO",
      "Number of local global offset table entries", ElfDynamicValueType.VALUE);
  // 0x7000000c-0x7000000f

  public static final ElfDynamicType DT_MIPS_GOTSYM =
    new ElfDynamicType(0x70000013, "DT_MIPS_GOTSYM",
      "Index of first dynamic symbol in global offset table", ElfDynamicValueType.VALUE);
  // 0x7000001f
  public static final ElfDynamicType DT_MIPS_OPTIONS = new ElfDynamicType(0x70000029,
    "DT_MIPS_OPTIONS", "Address of `.MIPS.options'", ElfDynamicValueType.ADDRESS);
  public static final ElfDynamicType DT_MIPS_GP_VALUE = new ElfDynamicType(0x70000030,
    "DT_MIPS_GP_VALUE", "GP value for auxiliary GOTs", ElfDynamicValueType.ADDRESS);
  public static final ElfDynamicType DT_MIPS_PLTGOT = new ElfDynamicType(0x70000032,
    "DT_MIPS_PLTGOT", "Address of the base of the PLTGOT", ElfDynamicValueType.ADDRESS);

  // MIPS-specific Symbol information
  // Special values for the st_other field in the symbol table entry for MIPS.
  public static final int STO_MIPS_PLT = 0x08; // PLT entry related dynamic table record

  // MIPS Option Kind
  public static final byte ODK_NULL = 0;
  public static final byte ODK_REGINFO = 1;
  public static final byte ODK_EXCEPTIONS = 2;
  public static final byte ODK_PAD = 3;
  public static final byte ODK_HWPATCH = 4;
  public static final byte ODK_FILL = 5;
  public static final byte ODK_TAGS = 6;
  public static final byte ODK_HWAND = 7;
  public static final byte ODK_HWOR = 8;
  public static final byte ODK_GP_GROUP = 9;
  public static final byte ODK_IDENT = 10;
  public static final byte ODK_PAGESIZE = 11;

  // MIPS-specific SHN values
  public static final short SHN_MIPS_ACOMMON = (short) 0xff00;
  public static final short SHN_MIPS_TEXT = (short) 0xff01;
  public static final short SHN_MIPS_DATA = (short) 0xff02;

  private final AuxRelocationProcessor auxRelocationProcessor = new AuxRelocationProcessor();

  @Override
  public boolean canHandle (ElfHeader elf) {
    return elf.e_machine() == PspElfConstants.INSTANCE.getEM_MIPS_PSP_HACK();
  }

  @Override
  public boolean canHandle (ElfLoadHelper elfLoadHelper) {
    Language language = elfLoadHelper.getProgram().getLanguage();
    return canHandle(elfLoadHelper.getElfHeader()) &&
      "Allegrex".equals(language.getProcessor().toString());
  }

  @Override
  public String getDataTypeSuffix () {
    return "_Allegrex";
  }

  @Override
  public Address calculateSymbolAddress (ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol) {

    if (!elfSymbol.hasProcessorSpecificSymbolSectionIndex()) {
      return null;
    }

    short sectionIndex = elfSymbol.getSectionHeaderIndex();
    if (sectionIndex == SHN_MIPS_ACOMMON || sectionIndex == SHN_MIPS_TEXT ||
      sectionIndex == SHN_MIPS_DATA) {
      // NOTE: logic assumes no memory conflict occured during section loading
      AddressSpace defaultSpace =
        elfLoadHelper.getProgram().getAddressFactory().getDefaultAddressSpace();
      return defaultSpace.getAddress(
        elfSymbol.getValue() + elfLoadHelper.getImageBaseWordAdjustmentOffset());
    }

    return null;
  }

  @Override
  public Address evaluateElfSymbol (ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol, Address address, boolean isExternal) {

    updateNonRelocatableGotEntries(elfLoadHelper, elfSymbol, address);

    if (isExternal) {
      return address;
    }

    String symName = elfSymbol.getNameAsString();
    if (StringUtils.isBlank(symName)) {
      return address;
    }

    if (elfSymbol.getType() == ElfSymbol.STT_FUNC) {
      if (!isExternal && (elfSymbol.getOther() & STO_MIPS_PLT) != 0) {
        elfLoadHelper.createExternalFunctionLinkage(symName, address, null);
      }
    }
    return address;
  }

  /**
   * Attempt to update external dynamic .got entries for non-relocatable binaries.
   * @param elfLoadHelper ELF load helper
   * @param elfSymbol ELF symbol being processed
   * @param address dynamic symbol address
   */
  private void updateNonRelocatableGotEntries (ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
                                               Address address) {

    ElfHeader elfHeader = elfLoadHelper.getElfHeader();
    if (elfHeader.isRelocatable() || !elfSymbol.getSymbolTable().isDynamic()) {
      return;
    }

    Long gotBaseOffset = elfLoadHelper.getGOTValue();
    if (gotBaseOffset == null) {
      return;
    }

    ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
    if (dynamicTable == null || !dynamicTable.containsDynamicValue(DT_MIPS_LOCAL_GOTNO) ||
      !dynamicTable.containsDynamicValue(DT_MIPS_GOTSYM)) {
      return;
    }

    try {
      int gotLocalEntryCount = (int) dynamicTable.getDynamicValue(DT_MIPS_LOCAL_GOTNO);
      int gotSymbolIndex = (int) dynamicTable.getDynamicValue(DT_MIPS_GOTSYM);

      int symbolIndex = elfSymbol.getSymbolTableIndex();
      if (symbolIndex < gotSymbolIndex) {
        return; // assume non-external symbol
      }

      int gotIndex = gotLocalEntryCount + (symbolIndex - gotSymbolIndex);

      Program program = elfLoadHelper.getProgram();

      Address gotBaseAddress =
        program.getAddressFactory().getDefaultAddressSpace().getAddress(gotBaseOffset);

      // Need to apply adjusted address since fixupGot will re-adjust for image base shift
      long imageShift = elfLoadHelper.getImageBaseWordAdjustmentOffset();
      long symbolOffset = address.getOffset() - imageShift;

      setTableEntryIfZero(gotBaseAddress, gotIndex, symbolOffset, elfLoadHelper);
    } catch (MemoryAccessException e) {
      Msg.error(this, "Failed to update .got table entry", e);
    } catch (NotFoundException e) {
      throw new AssertException("unexpected", e);
    }
  }

  @Override
  public void processElf (ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
    throws CancelledException {

    processMipsHeaders(elfLoadHelper, monitor);

    processMipsDyanmics(elfLoadHelper, monitor);
  }

  private void processMipsDyanmics (ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {

    ElfDynamicTable dynamicTable = elfLoadHelper.getElfHeader().getDynamicTable();
    if (dynamicTable != null && dynamicTable.containsDynamicValue(DT_MIPS_GP_VALUE)) {
      try {
        ElfHeader elf = elfLoadHelper.getElfHeader();
        long gpValue =
          elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(DT_MIPS_GP_VALUE));
        Address gpAddr = elfLoadHelper.getDefaultAddress(gpValue);
        elfLoadHelper.createSymbol(gpAddr, MIPS_GP_VALUE_SYMBOL, false, false, null);
        elfLoadHelper.log(MIPS_GP_VALUE_SYMBOL + "=0x" + Long.toHexString(gpValue));
      } catch (NotFoundException | InvalidInputException e) {
        // ignore
      }
    }
  }

  private void processMipsHeaders (ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {
    ElfHeader elf = elfLoadHelper.getElfHeader();

    Address mipsOptionsAddr = null;
    Address regInfoAddr = null;

    for (ElfProgramHeader programHeader : elf.getProgramHeaders()) {
      int headertype = programHeader.getType();
      if (headertype == PT_MIPS_OPTIONS.value) {
        mipsOptionsAddr = elfLoadHelper.findLoadAddress(programHeader, 0);
      } else if (headertype == PT_MIPS_REGINFO.value) {
        regInfoAddr = elfLoadHelper.findLoadAddress(programHeader, 0);
      }
    }

    for (ElfSectionHeader sectionHeader : elf.getSections()) {
      int headertype = sectionHeader.getType();
      if (headertype == SHT_MIPS_OPTIONS.value) {
        mipsOptionsAddr = elfLoadHelper.findLoadAddress(sectionHeader, 0);
      } else if (headertype == SHT_MIPS_REGINFO.value) {
        regInfoAddr = elfLoadHelper.findLoadAddress(sectionHeader, 0);
      }
    }

    if (mipsOptionsAddr == null) {
      ElfDynamicTable dynamicTable = elf.getDynamicTable();
      if (dynamicTable != null && dynamicTable.containsDynamicValue(DT_MIPS_OPTIONS)) {
        try {
          long optionsOffset =
            elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(DT_MIPS_OPTIONS));
          mipsOptionsAddr = elfLoadHelper.getDefaultAddress(optionsOffset);
        } catch (NotFoundException e) {
          throw new AssertException("unexpected", e);
        }
      }
    }

    if (mipsOptionsAddr != null) {
      processMipsOptions(elfLoadHelper, mipsOptionsAddr);
    }
    if (regInfoAddr != null) {
      // TODO: don't do this if mips options present and processed
      processMipsRegInfo(elfLoadHelper, regInfoAddr);
    }
  }

  private void processMipsOptions (ElfLoadHelper elfLoadHelper, Address mipsOptionsAddr) {

    boolean elf64 = elfLoadHelper.getElfHeader().is64Bit();
    String prefix = elf64 ? "Elf64" : "Elf32";

    EnumDataType odkType = new EnumDataType(prefix + "_MipsOptionKind", 1);
    odkType.add("ODK_NULL", ODK_NULL);
    odkType.add("ODK_REGINFO", ODK_REGINFO);
    odkType.add("ODK_EXCEPTIONS", ODK_EXCEPTIONS);
    odkType.add("ODK_PAD", ODK_PAD);
    odkType.add("ODK_HWPATCH", ODK_HWPATCH);
    odkType.add("ODK_FILL", ODK_FILL);
    odkType.add("ODK_TAGS", ODK_TAGS);
    odkType.add("ODK_HWAND", ODK_HWAND);
    odkType.add("ODK_HWOR", ODK_HWOR);
    odkType.add("ODK_GP_GROUP", ODK_GP_GROUP);
    odkType.add("ODK_IDENT", ODK_IDENT);
    odkType.add("ODK_PAGESIZE", ODK_PAGESIZE);

    Structure odkHeader =
      new StructureDataType(new CategoryPath("/ELF"), prefix + "_MipsOptionHeader", 0);
    odkHeader.add(odkType, "kind", null);
    odkHeader.add(ByteDataType.dataType, "size", null);
    odkHeader.add(WordDataType.dataType, "section", null);
    odkHeader.add(DWordDataType.dataType, "info", null);

    Memory memory = elfLoadHelper.getProgram().getMemory();
    long limit = 0;
    MemoryBlock block = memory.getBlock(mipsOptionsAddr);
    if (block != null) {
      limit = block.getEnd().subtract(mipsOptionsAddr) + 1;
    }

    Address nextOptionAddr = mipsOptionsAddr;
    int optionDataSize = 0;
    try {
      while (limit >= odkHeader.getLength()) {

        nextOptionAddr = nextOptionAddr.add(optionDataSize);
        byte kind = memory.getByte(nextOptionAddr);
        if (kind == 0) {
          break;
        }

        Data odkData = elfLoadHelper.createData(nextOptionAddr, odkHeader);
        if (odkData == null) {
          throw new MemoryAccessException();
        }

        int size = (memory.getByte(nextOptionAddr.next()) & 0xff) - odkData.getLength();
        optionDataSize = size + (size % 8);

        if (memory.getByte(nextOptionAddr) == 0) {
          break;
        }

        nextOptionAddr = nextOptionAddr.add(odkData.getLength());

        switch (kind) {

          case ODK_REGINFO:
            processMipsRegInfo(elfLoadHelper, nextOptionAddr);
            break;

          default:
            if (optionDataSize > 0) {
              // consume unprocessed option description bytes
              elfLoadHelper.createData(nextOptionAddr,
                new ArrayDataType(ByteDataType.dataType, optionDataSize, 1));
            }
        }

        limit -= odkHeader.getLength() + optionDataSize;
      }
    } catch (AddressOutOfBoundsException | MemoryAccessException e) {
      // ignore
    }
  }

  private Structure buildRegInfoStructure (boolean elf64) {

    String prefix = elf64 ? "Elf64" : "Elf32";

    EnumDataType gprMask = new EnumDataType(prefix + "_GPRMask_MIPS", 4);
    gprMask.add("gpr_zero", 1);
    gprMask.add("gpr_at", 2);
    gprMask.add("gpr_v0", 4);
    gprMask.add("gpr_v1", 8);
    gprMask.add("gpr_a0", 0x10);
    gprMask.add("gpr_a1", 0x20);
    gprMask.add("gpr_a2", 0x40);
    gprMask.add("gpr_a3", 0x80);
    gprMask.add("gpr_t0", 0x100);
    gprMask.add("gpr_t1", 0x200);
    gprMask.add("gpr_t2", 0x400);
    gprMask.add("gpr_t3", 0x800);
    gprMask.add("gpr_t4", 0x1000);
    gprMask.add("gpr_t5", 0x2000);
    gprMask.add("gpr_t6", 0x4000);
    gprMask.add("gpr_t7", 0x8000);
    gprMask.add("gpr_s0", 0x10000);
    gprMask.add("gpr_s1", 0x20000);
    gprMask.add("gpr_s2", 0x40000);
    gprMask.add("gpr_s3", 0x80000);
    gprMask.add("gpr_s4", 0x100000);
    gprMask.add("gpr_s5", 0x200000);
    gprMask.add("gpr_s6", 0x400000);
    gprMask.add("gpr_s7", 0x800000);
    gprMask.add("gpr_t8", 0x1000000);
    gprMask.add("gpr_t9", 0x2000000);
    gprMask.add("gpr_k0", 0x4000000);
    gprMask.add("gpr_k1", 0x8000000);
    gprMask.add("gpr_gp", 0x10000000);
    gprMask.add("gpr_sp", 0x20000000);
    gprMask.add("gpr_fp", 0x40000000);
    gprMask.add("gpr_ra", 0x80000000L);

    Structure regInfoStruct =
      new StructureDataType(new CategoryPath("/ELF"), prefix + "_RegInfo_MIPS", 0);
    regInfoStruct.add(gprMask, "ri_gprmask", null);
    if (elf64) {
      regInfoStruct.add(DWordDataType.dataType, "ri_pad", null);
    }
    regInfoStruct.add(new ArrayDataType(DWordDataType.dataType, 4, 4));
    if (elf64) {
      regInfoStruct.add(QWordDataType.dataType, "ri_gp_value", null);
    } else {
      regInfoStruct.add(DWordDataType.dataType, "ri_gp_value", null);
    }
    return regInfoStruct;
  }

  private void processMipsRegInfo (ElfLoadHelper elfLoadHelper, Address regInfoAddr) {

    // NOTES: assumes only one gp0 value

    AtomicBoolean multipleGp0 = new AtomicBoolean(false);
    Symbol gp0Sym = SymbolUtilities.getLabelOrFunctionSymbol(elfLoadHelper.getProgram(),
      MIPS_GP0_VALUE_SYMBOL, msg -> multipleGp0.set(true));
    Long otherGp0Value = gp0Sym != null ? gp0Sym.getAddress().getOffset() : null;

    AddressSpace defaultSpace =
      elfLoadHelper.getProgram().getAddressFactory().getDefaultAddressSpace();
    boolean is64bit = elfLoadHelper.getElfHeader().is64Bit();
    Structure regInfoStruct = buildRegInfoStructure(is64bit);

    Data data = elfLoadHelper.createData(regInfoAddr, regInfoStruct);
    Data gpValueComponent = data.getComponent(is64bit ? 3 : 2); // ri_gp_value value -> gp0
    if (gpValueComponent != null) {
      try {
        // Create gp0 symbol in default space which represents a constant value (pinned)
        Scalar gp0Value = gpValueComponent.getScalar(0);
        long gp0 = gp0Value.getUnsignedValue();
        if (multipleGp0.get() || otherGp0Value != null) {
          if (multipleGp0.get() || gp0 != otherGp0Value) {
            elfLoadHelper.log("Multiple gp0 values defined (not supported): 0x" +
              Long.toHexString(gp0));
          }
          return;
        }

        Address gpAddr = defaultSpace.getAddress(gp0);
        elfLoadHelper.createSymbol(gpAddr, MIPS_GP0_VALUE_SYMBOL, false, false, null)
          .setPinned(true);
        elfLoadHelper.log(MIPS_GP0_VALUE_SYMBOL + "=0x" + Long.toHexString(gp0));
      } catch (InvalidInputException e) {
        // ignore
      }
    }

  }

  @Override
  public void processGotPlt (ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {
    // Only possible injection point into the loading process after processing relocation and imports
    monitor.setMessage("Processing additional relocations...");
    boolean useRebootBinTypeBMapping = false;
    if (elfLoadHelper.getElfHeader() instanceof PspElfHeader) {
      useRebootBinTypeBMapping = ((PspElfHeader) elfLoadHelper.getElfHeader()).getUseRebootBinTypeBMapping();
    }
    auxRelocationProcessor.process(elfLoadHelper, useRebootBinTypeBMapping);

    monitor.setMessage("Processing PLT/GOT...");
    fixupGot(elfLoadHelper, monitor);

    fixupMipsGot(elfLoadHelper, monitor);

    super.processGotPlt(elfLoadHelper, monitor);

    processMipsStubsSection(elfLoadHelper, monitor);
  }

  private void processMipsStubsSection (ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
    throws CancelledException {

    Memory memory = elfLoadHelper.getProgram().getMemory();
    MemoryBlock stubsBlock = memory.getBlock(MIPS_STUBS_SECTION_NAME);
    if (stubsBlock == null || !stubsBlock.isExecute()) {
      return;
    }

    ElfDefaultGotPltMarkup defaultGotPltMarkup = new ElfDefaultGotPltMarkup(elfLoadHelper);
    defaultGotPltMarkup.processLinkageTable(MIPS_STUBS_SECTION_NAME, stubsBlock.getStart(),
      stubsBlock.getEnd(), monitor);
  }

  private void fixupGot (ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
    throws CancelledException {

    // see Wiki at  https://dmz-portal.mips.com/wiki/MIPS_Multi_GOT
    // see related doc at https://www.cr0.org/paper/mips.elf.external.resolution.txt

    ElfHeader elfHeader = elfLoadHelper.getElfHeader();
    ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
    ElfSymbolTable dynamicSymbolTable = elfHeader.getDynamicSymbolTable();
    if (dynamicTable == null || dynamicSymbolTable == null) {
      return;
    }

    // Ensure that we can get the required dynamic entries to avoid NotFoundException
    if (!dynamicTable.containsDynamicValue(DT_MIPS_LOCAL_GOTNO) ||
      !dynamicTable.containsDynamicValue(DT_MIPS_GOTSYM)) {
      return;
    }
    Program program = elfLoadHelper.getProgram();
    Long gotBaseOffset = elfLoadHelper.getGOTValue();
    if (gotBaseOffset == null) {
      return;
    }

    Address gotBaseAddress =
      program.getAddressFactory().getDefaultAddressSpace().getAddress(gotBaseOffset);

    try {

      ElfSymbol[] elfSymbols = dynamicSymbolTable.getSymbols();

      int gotLocalEntryCount = (int) dynamicTable.getDynamicValue(DT_MIPS_LOCAL_GOTNO);
      int gotSymbolIndex = (int) dynamicTable.getDynamicValue(DT_MIPS_GOTSYM);

      long imageShift = elfLoadHelper.getImageBaseWordAdjustmentOffset();

      // process local symbol got entries
      for (int i = 0; i < gotLocalEntryCount; i++) {
        monitor.checkCancelled();
        Address gotEntryAddr =
          adjustTableEntryIfNonZero(gotBaseAddress, i, imageShift, elfLoadHelper);
        Data pointerData = elfLoadHelper.createData(gotEntryAddr, PointerDataType.dataType);
        if (ElfDefaultGotPltMarkup.isValidPointer(pointerData)) {
          ElfDefaultGotPltMarkup.setConstant(pointerData);
        }
      }

      // process global/external symbol got entries
      int gotIndex = gotLocalEntryCount;
      for (int i = gotSymbolIndex; i < elfSymbols.length; i++) {
        monitor.checkCancelled();
        Address gotEntryAddr = adjustTableEntryIfNonZero(gotBaseAddress, gotIndex++,
          imageShift, elfLoadHelper);
        Data pointerData = elfLoadHelper.createData(gotEntryAddr, PointerDataType.dataType);
        ElfDefaultGotPltMarkup.setConstant(pointerData);
        if (elfSymbols[i].isFunction() && elfSymbols[i].getSectionHeaderIndex() == 0) {
          // ensure that external function/thunk are created in absence of sections
          String symName = elfSymbols[i].getNameAsString();
          if (!StringUtils.isBlank(symName)) {
            Address refAddr = (Address) pointerData.getValue();
            elfLoadHelper.createExternalFunctionLinkage(symName, refAddr, gotEntryAddr);
          }
        }
      }
    } catch (NotFoundException e) {
      throw new AssertException("unexpected", e);
    } catch (MemoryAccessException e) {
      elfLoadHelper.log("Failed to adjust GOT: " + e.getMessage());
    }
  }

  private void fixupMipsGot (ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {

    ElfHeader elfHeader = elfLoadHelper.getElfHeader();
    ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
    ElfSymbolTable dynamicSymbolTable = elfHeader.getDynamicSymbolTable();
    if (dynamicTable == null || dynamicSymbolTable == null) {
      return;
    }

    ElfSymbol[] elfSymbols = dynamicSymbolTable.getSymbols();

    // Ensure that we can get the required dynamic entries to avoid NotFoundException
    if (!dynamicTable.containsDynamicValue(DT_MIPS_PLTGOT) ||
      !dynamicTable.containsDynamicValue(DT_MIPS_GOTSYM)) {
      return;
    }

    Program program = elfLoadHelper.getProgram();

    Symbol mipsPltgotSym = SymbolUtilities.getLabelOrFunctionSymbol(program, "__DT_MIPS_PLTGOT",
      err -> elfLoadHelper.getLog().appendMsg(err));
    if (mipsPltgotSym == null) {
      return; // unexpected
    }
    Address mipsPltgotBase = mipsPltgotSym.getAddress();

    try {

      int gotSymbolIndex = (int) dynamicTable.getDynamicValue(DT_MIPS_GOTSYM);

      long imageShift = elfLoadHelper.getImageBaseWordAdjustmentOffset();

      // process global dynamic symbol got entries
      int gotEntryIndex = 1;
      for (int i = 0; i < gotSymbolIndex; i++) {
        monitor.checkCancelled();
        if (!elfSymbols[i].isFunction() || !elfSymbols[i].isGlobal() ||
          elfSymbols[i].getSectionHeaderIndex() != 0) {
          continue;
        }
        Address gotEntryAddr = adjustTableEntryIfNonZero(mipsPltgotBase, ++gotEntryIndex,
          imageShift, elfLoadHelper);
        Data pointerData = elfLoadHelper.createData(gotEntryAddr, PointerDataType.dataType);
        ElfDefaultGotPltMarkup.setConstant(pointerData);
      }
    } catch (NotFoundException e) {
      throw new AssertException("unexpected", e);
    } catch (MemoryAccessException e) {
      elfLoadHelper.log("Failed to adjust MIPS GOT: " + e.getMessage());
    }
  }

  private Address adjustTableEntryIfNonZero (Address tableBaseAddr, int entryIndex,
                                             long adjustment, ElfLoadHelper elfLoadHelper)
    throws MemoryAccessException {
    boolean is64Bit = elfLoadHelper.getElfHeader().is64Bit();
    Memory memory = elfLoadHelper.getProgram().getMemory();
    Address tableEntryAddr;
    if (is64Bit) {
      tableEntryAddr = tableBaseAddr.add(entryIndex * 8);
      if (adjustment != 0) {
        long offset = memory.getLong(tableEntryAddr);
        long newValue = offset + adjustment;
        if (offset != 0 && offset != newValue) {
          elfLoadHelper.addArtificialRelocTableEntry(tableEntryAddr, 8);
          memory.setLong(tableEntryAddr, newValue);
        }
      }
    } else {
      tableEntryAddr = tableBaseAddr.add(entryIndex * 4);
      if (adjustment != 0) {
        int offset = memory.getInt(tableEntryAddr);
        int newValue = (int) (offset + adjustment);
        if (offset != 0 && offset != newValue) {
          elfLoadHelper.addArtificialRelocTableEntry(tableEntryAddr, 4);
          memory.setInt(tableEntryAddr, newValue);
        }
      }
    }
    return tableEntryAddr;
  }

  private Address setTableEntryIfZero (Address tableBaseAddr, int entryIndex, long value,
                                       ElfLoadHelper elfLoadHelper) throws MemoryAccessException {
    boolean is64Bit = elfLoadHelper.getElfHeader().is64Bit();
    Memory memory = elfLoadHelper.getProgram().getMemory();
    Address tableEntryAddr;
    if (is64Bit) {
      tableEntryAddr = tableBaseAddr.add(entryIndex * 8);
      long offset = memory.getLong(tableEntryAddr);
      if (offset == 0 && value != 0) {
        elfLoadHelper.addArtificialRelocTableEntry(tableEntryAddr, 8);
        memory.setLong(tableEntryAddr, value);
      }
    } else {
      tableEntryAddr = tableBaseAddr.add(entryIndex * 4);
      int offset = memory.getInt(tableEntryAddr);
      if (offset == 0 && value != 0) {
        elfLoadHelper.addArtificialRelocTableEntry(tableEntryAddr, 4);
        memory.setInt(tableEntryAddr, (int) value);
      }
    }
    return tableEntryAddr;
  }

  @Override
  public Class<? extends ElfRelocation> getRelocationClass (ElfHeader elfHeader) {
    return AllegrexElfRelocationExtension.class;
  }

  @Override
  public Long getSectionSymbolRelativeOffset (ElfSectionHeader symSection, Address symSectionBase,
                                              ElfSymbol elfSymbol) {

    // NOTE: PSP PRX files should really be wired to ElfHeader.isRelocatable(), however we do
    // not support the associated relocation tables so we do offer the image base option
    // during import.  If image base should be changed we leave that to a user script to change
    // the image base and process the relocation tables as needed.
    if (symSection.getElfHeader().e_type() == ET_MIPS_PSP_PRX) {
      return elfSymbol.getValue();
    }

    return super.getSectionSymbolRelativeOffset(symSection, symSectionBase, elfSymbol);
  }

}
