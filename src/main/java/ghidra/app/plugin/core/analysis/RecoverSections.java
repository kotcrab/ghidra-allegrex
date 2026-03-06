// Recover some section names and apply NIDs for PSP binaries.
// Adapted from the original Python script by Ethanol.
// @author Ethanol (Original Script)
// @author SHADOW (Ghidra Java Implementation)
// @category Analysis

package allegrex.analysis;

// Ghidra
import static ghidra.app.util.Utils.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class RecoverSections {

    public static void RecoverSections(Program program, boolean nid) throws Exception {

        Data sceModuleInfo = findAndModuleInfoStruct(program);
        Data modNameData = sceModuleInfo.getComponent(2);
        byte[] bytes = modNameData.getBytes();
        String moduleName = new String(bytes).trim().replace(" ", "_");

        long gp = sceModuleInfo.getComponent(4).getUnsignedInt(0);
        if (gp != 0) addLabel(program, toAddr(program, gp), "_gp", true, true);
        SectionTracker tracker = new SectionTracker();
        
        // Exports
        Address exportsAddr = toAddr(program, sceModuleInfo.getComponent(5).getUnsignedInt(0));
        Address exportsEnd = toAddr(program, sceModuleInfo.getComponent(6).getUnsignedInt(0));
        Address exportsTop = exportsAddr.subtract(4);

        if (exportsAddr.getOffset() > exportsEnd.getOffset()) {
            throw new Exception("Irrelar exports data");
        }
        long size = exportsEnd.getOffset() - exportsAddr.getOffset();
        createMemBlock(program, exportsTop, 4, ".lib.ent.top", true, false, false);

        if (size != 0) {
            createMemBlock(program, exportsAddr, (int) size, ".lib.ent", true, false, false);
        }

        createMemBlock(program, exportsEnd, 4, ".lib.ent.btm", true, false, false);

        addLabel(program, exportsTop, "_begin_of_section_lib_ent", true, false);
        addLabel(program, exportsEnd, "_end_of_section_lib_ent", true, false);

        AllegrexResolveExports test2 = new AllegrexResolveExports(program);
        test2.Resolve(exportsAddr, exportsEnd, moduleName, tracker, nid);

        // imports
        
        Address importsAddr = toAddr(program, sceModuleInfo.getComponent(7).getUnsignedInt(0));
        Address importsEnd = toAddr(program, sceModuleInfo.getComponent(8).getUnsignedInt(0));
        Address importsTop = importsAddr.subtract(4);

        if (importsAddr.getOffset() > importsEnd.getOffset()) {
            throw new Exception("Irregular exports data");
        }

        long ImportsSize = importsEnd.getOffset() - importsAddr.getOffset();
        createMemBlock(program, importsTop, 4, ".lib.stub.top", true, false, false);

        if (ImportsSize != 0) createMemBlock(program, importsAddr, (int)ImportsSize, ".lib.stub", true, false, false);
        createMemBlock(program, importsEnd, 4, ".lib.stub.btm", true, false, false);

        addLabel(program, importsTop, "_begin_of_section_lib_stub", true, false);
        addLabel(program, importsEnd, "_end_of_section_lib_stub", true, false);

        AllegrexResolveImports test = new AllegrexResolveImports(program);
        test.Resolve(importsAddr, importsEnd, tracker, nid);
        
        if (tracker.sceResidentStart != null) {
            createMemBlock(program, tracker.sceResidentStart, tracker.sceResidentSize, ".rodata.sceResident", true, false, false);
        }
        if (tracker.sceNidStart != null) {
            createMemBlock(program, tracker.sceNidStart, tracker.sceResidentSize, ".rodata.sceResident", true, false, false);
        }

    }
    private static Data findAndModuleInfoStruct(Program program) throws Exception {
        Structure sceModuleInfoDt = createModuleInfoStruct(program);
        int sceModuleInfoDt_len = sceModuleInfoDt.getLength();

        Memory memory = program.getMemory();
        Listing listing = program.getListing();

        // .lib.stub
        MemoryBlock sceModuleInfo_section = program.getMemory().getBlock(".rodata.sceModuleInfo");
        Address sceModuleInfoAddr;
        if (sceModuleInfo_section == null) {
            System.out.println("Could not find .rodata.sceModuleInfo section, calculating its location from elf program header");
            sceModuleInfoAddr = getModuleInfoAddrFromLoadCommands(program);
        } else {
            sceModuleInfoAddr = sceModuleInfo_section.getStart();
        }

        createMemBlock(program, sceModuleInfoAddr, sceModuleInfoDt_len, ".rodata.sceModuleInfo", true, false, false);
        placeDataType(program, sceModuleInfoAddr, sceModuleInfoDt);

        return listing.getDataAt(sceModuleInfoAddr);
    }

    private static Structure createModuleInfoStruct(Program program) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Enum SceModuleAttr
        EnumDataType sceModuleAttr = new EnumDataType(new CategoryPath("/PSP"), "SceModuleAttr", 1);
        sceModuleAttr.add("NONE", 0x00);
        sceModuleAttr.add("CANT_STOP", 0x01, "Resident module - stays in memory");
        sceModuleAttr.add("EXCLUSIVE_LOAD", 0x02, "Only one instance of the module can be loaded");
        sceModuleAttr.add("EXCLUSIVE_START", 0x04, "Only one instance of the module can be started");

        // Enum SceModulePriv
        EnumDataType sceModulePriv = new EnumDataType(new CategoryPath("/PSP"), "SceModulePriv", 1);
        sceModulePriv.add("USER", 0x00, "Lowest permission");
        sceModulePriv.add("MS", 0x02, "POPS/Demo");
        sceModulePriv.add("USB_WLAN", 0x04, "Module Gamesharing");
        sceModulePriv.add("APP", 0x06, "Application module");
        sceModulePriv.add("VSH", 0x08, "VSH module");
        sceModulePriv.add("KERNEL", 0x10, "Highest permission");
        sceModulePriv.add("KIRK_MEMLMD_LIB", 0x20, "Uses KIRK memlmd lib");
        sceModulePriv.add("KIRK_SEMAPHORE_LIB", 0x40, "Uses KIRK semaphore lib");

        // Struct SceModuleAttributes
        StructureDataType sceModuleAttributes = new StructureDataType(new CategoryPath("/PSP"), "SceModuleAttributes", 0);
        sceModuleAttributes.add(sceModuleAttr, "attribute", null);
        sceModuleAttributes.add(sceModulePriv, "privilege", null);

        // Struct SceModuleInfo
        StructureDataType sceModuleInfo = new StructureDataType(new CategoryPath("/PSP"), "SceModuleInfo", 0);
        sceModuleInfo.add(sceModuleAttributes, "modattribute", null);
        sceModuleInfo.add(new ArrayDataType(ByteDataType.dataType, 2, 1), "modversion", null);
        sceModuleInfo.add(new ArrayDataType(ByteDataType.dataType, 27, 1), "modname", null);
        sceModuleInfo.add(ByteDataType.dataType, "terminal", null);
        sceModuleInfo.add(new PointerDataType(VoidDataType.dataType), "gp_value", null);
        sceModuleInfo.add(new PointerDataType(VoidDataType.dataType), "ent_top", null);
        sceModuleInfo.add(new PointerDataType(VoidDataType.dataType), "ent_end", null);
        sceModuleInfo.add(new PointerDataType(VoidDataType.dataType), "stub_top", null);
        sceModuleInfo.add(new PointerDataType(VoidDataType.dataType), "stub_end", null);

        // registrar no DataTypeManager
        DataType existing = dtm.addDataType(sceModuleInfo, DataTypeConflictHandler.DEFAULT_HANDLER);
        return (Structure) existing;
    }

    private static Address getModuleInfoAddrFromLoadCommands(Program program) throws Exception {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();

        MemoryBlock elfHeaders = memory.getBlock("_elfProgramHeaders");
        if (elfHeaders == null) {
            throw new Exception("_elfProgramHeaders section not found");
        }

        Data loadCmds = listing.getDataAt(elfHeaders.getStart());
        if (loadCmds == null) {
            throw new Exception("No data found at _elfProgramHeaders start");
        }

        // Fisrt load commnad
        Data loadCmd = loadCmds.getComponent(0);
        // 2nd component is p_offset
        long loadOffset = loadCmd.getComponent(1).getLong(0);
        // 4nd component is p_addr
        long loadPaddr = loadCmd.getComponent(3).getLong(0);

        // kernel prx (?????)
        loadPaddr &= 0x7FFFFFFF;
        loadPaddr = loadPaddr - loadOffset;

        // Create Addres to loapaddr
        Address sceModuleInfoAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(loadPaddr);

        long imageBase = program.getImageBase().getOffset();
        sceModuleInfoAddr = sceModuleInfoAddr.add(imageBase);

        return sceModuleInfoAddr;
    }

}
