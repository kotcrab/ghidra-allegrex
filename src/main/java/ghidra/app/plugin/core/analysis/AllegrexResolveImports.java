// Recover some section names and apply NIDs for PSP binaries.
// Adapted from the original Python script by Ethanol.
// @author Ethanol (Original Script)
// @author SHADOW (Ghidra Java Implementation)
// @category Analysis
package allegrex.analysis;

// Ghidra Util Static
import static ghidra.app.util.Utils.*;

// Ghidra depedenced
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.util.ModuleType;

// Java depedence
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class AllegrexResolveImports {

    private Program program;
    private Memory memory;
    private SymbolTable symbolTable;
    private ExternalManager extMan;
    private FunctionManager functionManager;

    public AllegrexResolveImports (Program program) {
        this.program = program;
        this.memory = program.getMemory();
        this.symbolTable = program.getSymbolTable();
        this.extMan = program.getExternalManager();
        this.functionManager = program.getFunctionManager();
    }
    
    public void Resolve(Address imports_addr, Address imports_end, SectionTracker tracker, Boolean resolveNid) throws Exception {

        Object[] dts = createModuleImportStructs(program);
        Structure dt1 = (Structure) dts[0];
        Structure dt2 = (Structure) dts[1];
        Structure dt3 = (Structure) dts[2];
        DataType relocDt = (DataType) dts[3];

        int importDtLen = dt1.getLength();
        long entSize = imports_end.getOffset() - imports_addr.getOffset();

        program.getListing().clearCodeUnits(imports_addr, imports_end, false);

        int total_nids = 0;
        List<Long> nidAddrs = new ArrayList<>();
        List<Long> sceResGuesses = new ArrayList<>();

        List<Data> modules = new ArrayList<>();
        Address addr = imports_addr;

        while (addr.add(importDtLen).compareTo(imports_end) <= 0) {
            byte entryLen = memory.getByte(addr.add(8));

            if (entryLen == 5) {
                placeDataType(program, addr, dt1);
            } else if (entryLen == 6) {
                placeDataType(program, addr, dt2);
            } else if (entryLen == 7) {
                placeDataType(program, addr, dt3);
            } else {
                //throw new ExecutionControl.RunException("Unkowm Import struct Size: " + entryLen);
            }
            Data module = program.getListing().getDataAt(addr);
            modules.add(module);
            addr = addr.add(4L * entryLen);
        }
        tracker.sceResidentSize += modules.size() * 4;

        for (Data module : modules) {

            Address moduleNameAddr = (Address) module.getComponent(0).getValue();
            String moduleName;

            if (moduleNameAddr.getOffset() != 0) {
                moduleName = getCString(program, moduleNameAddr);
                placeDataType(program, moduleNameAddr, TerminatedStringDataType.dataType, moduleName.length() + 1);
                tracker.sceResidentSize += ((moduleName.length() + 1) + 3) & ~3;
            } else {
                moduleName = "unknown";
            }

            int version = module.getComponent(1).getUnsignedShort(0);

            if (moduleNameAddr.getOffset() != 0) {
                Address versionAddr = moduleNameAddr.subtract(4);

                addLabel(program, versionAddr, String.format("_sce_package_version_%s", moduleName), false, true);
                placeDataType(program, versionAddr, UnsignedIntegerDataType.dataType);

                int raw = memory.getShort(versionAddr) & 0xFFFF;

                String verStr = String.format(
                        "v%d.%d.%d.%d",
                        raw & 0xF,
                        (raw >> 4) & 0XF,
                        (raw >> 8) & 0XF,
                        (raw >> 12) & 0XF
                );

                sceResGuesses.add(moduleNameAddr.subtract(4).getOffset());
                addLabel(program, moduleNameAddr, String.format("_%s_stub_str", moduleName), true, true);
            }

            addLabel(program, module.getAddress(), String.format("_%s_%04X_stub_head", moduleName, version), true, true);

            Library lib = extMan.getExternalLibrary(moduleName);
            if (lib == null) lib = extMan.addExternalLibraryName(moduleName, SourceType.ANALYSIS);

            int numVars = module.getComponent(4).getUnsignedByte(0);
            int numFuncs = module.getComponent(5).getUnsignedShort(0);
            Address nidsBase = (Address) module.getComponent(6).getValue();
            Address stubBase = (Address) module.getComponent(7).getValue();

            Data varsBaseData = module.getComponent(8);
            Data numVars2 = module.getComponent(9);

            if (numVars2 != null) {
                int v = numVars2.getUnsignedShort(0);
                if (v > numVars) {
                    numVars = v;
                }
            }

            Address varsBase = null;

            if (varsBaseData != null) {
                varsBase = (Address) varsBaseData.getValue();
            }

            if (numVars != 0 && varsBase != null && varsBase.getOffset() == 0) {
                throw new IllegalStateException(
                        "Import Module has vars yet no variable stub offset provided"
                );
            }

            total_nids += numFuncs;
            
            if(nidsBase.getOffset() != 0) {
                nidAddrs.add(nidsBase.getOffset());
                placeDataType(program, nidsBase, new ArrayDataType(UnsignedIntegerDataType.dataType, numFuncs, 4));
                addLabel(program, nidsBase, moduleName + "_nids", true, false);
            }
            
            // Resolver Functions
            for (int i = 0; i < numFuncs; i++) {
                Address nidAddr = nidsBase.add(4 * i);
                Address stubAddr = stubBase.add(8 * i);

                String nidHex = String.format("0x%08X", memory.getInt(nidAddr));

                String funcName = getNameForNID(moduleName, nidHex);

                Function f = functionManager.getFunctionAt(stubAddr);

                if (f == null) {
                    f = functionManager.createFunction(funcName, stubAddr, new AddressSet(stubAddr), SourceType.ANALYSIS);
                } else if (!funcName.equals(f.getName())) {
                    f.setName(funcName, SourceType.ANALYSIS);
                }
                ModuleType moduleClass = new ModuleType(program);
                moduleClass.createModule(moduleName);
                moduleClass.applyFunctionSignature(moduleName, nidHex, f);

                ExternalLocation extLoc = extMan.addExtFunction(
                        lib,
                        funcName,
                        stubAddr,
                        SourceType.ANALYSIS
                );

                Function extFunc = extLoc.getFunction();

                if (extFunc != null) {
                    moduleClass.applyFunctionSignature(moduleName, nidHex, extFunc);
                    f.setThunkedFunction(extFunc);
                }

                makeExternal(stubAddr, symbolTable);

            }

            if (numFuncs > 0) tracker.funcStubs.add(new StubInfo(moduleName, stubBase, numFuncs * 8));
            int extra_var_bytes = 0;

            for (int i = 0; i < numVars; i++) {
                Address stubAddr = varsBase.add(8 * i);
                Address nidAddr = varsBase.add(8 * i + 4);
                program.getListing().clearCodeUnits(stubAddr, stubAddr.add(8 - 1), false);

                placeDataType(program, stubAddr, PointerDataType.dataType);
                placeDataType(program, nidAddr, UnsignedIntegerDataType.dataType);
                String nidHex = String.format("0x%08X", memory.getInt(nidAddr));
                String vName = nidHex;

                long relOffset = memory.getInt(stubAddr) & 0xFFFFFFFFL;
                Address relAddr = toAddr(program, relOffset);

                int relocIndex = 0;

                while (true) {

                    int value = memory.getInt(
                            relAddr.add(relocIndex * 4)
                    );

                    relocIndex++;

                    if (value == 0) {
                        break;
                    }

                    long rAddrOffset = (value & 0x03FFFFFFL) * 4;
                    Address rAddr = toAddr(program,rAddrOffset);

                    int rtype = (value >>> 26) & 0x3F;

                    String msg;

                    switch (rtype) {

                        case 5:
                            msg = "R_MIPS_HI16: " + vName + " from " + moduleName;
                            break;

                        case 6:
                            msg = "R_MIPS_LO16: " + vName + " from " + moduleName;
                            break;

                        case 2:
                            msg = "R_MIPS_32: " + vName + " from " + moduleName;
                            break;

                        default:
                            msg = "MIPS_RELOC " + rtype + ": " + vName + " from " + moduleName;
                            break;
                    }
                    
                    //program.getListing().setComment(rAddr, CodeUnit.EOL_COMMENT, msg);
                    extra_var_bytes += relocIndex * 4;
                }
                if (numVars > 0) {
                tracker.varsStubs.add(new StubInfo(moduleName, varsBase, numVars * 8 + extra_var_bytes));
                }
            }

            tracker.sceNidStart = toAddr(program, Collections.min(nidAddrs));
            tracker.sceNidSize = total_nids * 4;

            long guess = Collections.min(sceResGuesses);

            if (tracker.sceResidentStart == null
                    || guess < tracker.sceResidentStart.getOffset()) {
                tracker.sceResidentStart = toAddr(program, guess);
            }
            
        }
    }
        private static Object[] createModuleImportStructs(Program program) throws Exception {
        DataTypeManager dataTypeManager = program.getDataTypeManager();

        EnumDataType sceLibAttr = new EnumDataType(new CategoryPath("/PSP"), "SceLibAttr", 2);
        EnumDataType varRelType = new EnumDataType(new CategoryPath("/PSP"), "VarRelocType", 4);
        StructureDataType sceStub_dt = new StructureDataType(new CategoryPath("/PSP"), "SceStubLibEntry", 0);
        StructureDataType reloc = new StructureDataType(new CategoryPath("/PSP"), "SceVarRelocEntry", 0);

        sceLibAttr.add("NO_SPECIAL_ATTR", 0x0000, "The library has no special attributes");
        sceLibAttr.add("AUTO_EXPORT", 0x0001, "Automatically register the library to the system");
        sceLibAttr.add("WEAK_EXPORT", 0x0002, "Indicates resident library can be overwritten");
        sceLibAttr.add("NOLINK_EXPORT", 0x0004, "Indicates resident library is NOT being linked");
        sceLibAttr.add("WEAK_IMPORT", 0x0008, "Load module that references this library even if this library is not registered");
        sceLibAttr.add("SYSCALL_EXPORT", 0x4000, "Indicates the use of the SYSCALL technique for linking");
        sceLibAttr.add("SCE_LIB_IS_SYSLIB", 0x8000, "The library is a system library");

        dataTypeManager.addDataType(sceLibAttr, DataTypeConflictHandler.DEFAULT_HANDLER);

        sceStub_dt.add(new PointerDataType(CharDataType.dataType), "libname", null);
        sceStub_dt.add(new ArrayDataType(ByteDataType.dataType, 2, 1), "version", null);
        sceStub_dt.add(sceLibAttr, "attribute", null);
        sceStub_dt.add(ByteDataType.dataType, "size", null);
        sceStub_dt.add(ByteDataType.dataType, "num_vars", null);
        sceStub_dt.add(UnsignedShortDataType.dataType, "num_funcs", null);
        sceStub_dt.add(new PointerDataType(VoidDataType.dataType), "nids_ptr", null);
        sceStub_dt.add(new PointerDataType(VoidDataType.dataType), "stubs_ptr", null);


        Structure dt1 = (Structure) dataTypeManager.addDataType( sceStub_dt, DataTypeConflictHandler.DEFAULT_HANDLER);

        sceStub_dt.setName("SceStubLibEntryVar");
        sceStub_dt.add(new PointerDataType(VoidDataType.dataType), "vars_ptr", null);

        Structure dt2 = (Structure) dataTypeManager.addDataType( sceStub_dt, DataTypeConflictHandler.DEFAULT_HANDLER);

        sceStub_dt.setName("SceStubLibEntryVarEx");
        sceStub_dt.add(UnsignedShortDataType.dataType, "num_vars_2", null);
        sceStub_dt.add(UnsignedShortDataType.dataType, "padding", null);

        Structure dt3 = (Structure) dataTypeManager.addDataType(sceStub_dt, DataTypeConflictHandler.DEFAULT_HANDLER);

        varRelType.add("R_MIPS_NOME", 0);
        varRelType.add("R_MIPS_32", 2);
        varRelType.add("R_MIPS_H16", 5);
        varRelType.add("R_MIPS_LO16", 6);

        dataTypeManager.addDataType(varRelType, DataTypeConflictHandler.DEFAULT_HANDLER);

        reloc.setPackingEnabled(true);
        reloc.addBitField(UnsignedIntegerDataType.dataType, 26, "addr", null);
        reloc.addBitField(varRelType, 6, "rel_type", null);

        DataType relDt = dataTypeManager.addDataType(reloc, DataTypeConflictHandler.DEFAULT_HANDLER);
        return new Object[]{dt1, dt2, dt3, relDt};
    }
}