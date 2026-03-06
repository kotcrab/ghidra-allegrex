package allegrex.analysis;
// Ghidra Util Static

import static ghidra.app.util.Utils.*;

// Ghidra depedenced
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.Listing;

// Java depedence
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class AllegrexResolveExports {

    private Program program;
    private Memory memory;
    private SymbolTable symbolTable;
    private ExternalManager extMan;
    private FunctionManager functionManager;

    public AllegrexResolveExports(Program program) {
        this.program = program;
        this.memory = program.getMemory();
        this.symbolTable = program.getSymbolTable();
        this.extMan = program.getExternalManager();
        this.functionManager = program.getFunctionManager();
    }

    public void Resolve(Address exportsAddr, Address exportsEnd, String moduleName, SectionTracker tracker, Boolean resolveNid) throws Exception {

        int[] pivotTableSizes = {
            0x0,
            0x4,
            0x10,
            0x20,
            0x40,
            0x80,
            0x100,
            0x200};

        Structure[] exportDts = createModuleExportStructs(program);

        Structure exportDt1 = exportDts[0];
        Structure exportDt2 = exportDts[1];
        int exportDtLen = exportDt1.getLength();

        long size = exportsEnd.getOffset() - exportsAddr.getOffset();
        if (size < exportDtLen) {
            return;
        }
        program.getListing().clearCodeUnits(exportsAddr, exportsEnd, false);

        Address addr = exportsAddr;
        List<Data> modules = new ArrayList<>();
        List<Long> sceResGuesses = new ArrayList<>();

        while (addr.add(exportDtLen).compareTo(exportsEnd) <= 0) {

            byte entryLen = memory.getByte(addr.add(8));

            if (entryLen == 4) {
                placeDataType(program, addr, exportDt1);
            } else if (entryLen == 5) {
                placeDataType(program, addr, exportDt2);
            } else {
                throw new RuntimeException("Unknown export entry size: " + entryLen);
            }

            Data module = program.getListing().getDataAt(addr);
            modules.add(module);

            addr = addr.add(4L * entryLen);
        }

        int module_index = 0;
        for (Data module : modules) {

            Address module_name_addr = (Address) module.getComponent(0).getValue();
            String module_name;

            if (module_name_addr.getOffset() != 0) {
                module_name = getCString(program, module_name_addr);
                program.getListing().createData(module_name_addr, new TerminatedStringDataType(), module_name.length() + 1);
                sceResGuesses.add(module_name_addr.getOffset());
                tracker.sceResidentSize += ((module_name.length() + 1) + 3) & ~3;
            }
            if (module_index == 0) {
                module_name = moduleName;
            } else {
                module_name = "unknown";
            }
            module_index += 1;
            int version = module.getComponent(1).getUnsignedShort(0);

            if (module_name_addr.getOffset() != 0) {
                addLabel(program, module_name_addr, String.format("_%s_ent_str", module_name), false, true);

            }
            addLabel(program, module.getAddress(), String.format("_%s_%04X_ent_head", module_name, version), false, true);

            int numVars = module.getComponent(4).getUnsignedByte(0);
            int numFuncs = module.getComponent(5).getUnsignedShort(0);
            Address nids_base = (Address) module.getComponent(6).getValue();
            Data num_vars_2 = module.getComponent(7);
            Data func_pivot = module.getComponent(8);
            Data var_pivot = module.getComponent(9);
            Data num_alias = module.getComponent(10);
            sceResGuesses.add(nids_base.getOffset());

            if (num_vars_2 != null) {
                int tmp = num_vars_2.getUnsignedShort(0);
                if (tmp > numVars) {
                    numVars = tmp;
                }
            }

            int total_nids = numVars + numFuncs;
            tracker.sceResidentSize += total_nids * 8;

            Address stubBase = nids_base.add(total_nids * 4);
            int num_func_pivots = 0;

            if (func_pivot != null) {
                int p = (int) ((Scalar) func_pivot.getValue()).getUnsignedValue();
                if (p != 0) {
                    num_func_pivots = pivotTableSizes[p];
                }
            }
            int varPivotCount = 0;
            if (var_pivot != null) {
                int p = (int) ((Scalar) var_pivot.getValue()).getUnsignedValue();
                if (p < pivotTableSizes.length) {
                    varPivotCount = pivotTableSizes[p];
                }
            }

            int total_pivots = num_func_pivots + varPivotCount;
            tracker.sceResidentSize += total_pivots * 2;

            int aliasCount = 0;
            if (num_alias != null && num_alias.getValue() instanceof Scalar) {
                aliasCount = (int) ((Scalar) num_alias.getValue()).getUnsignedValue();
            }

            tracker.sceResidentSize += aliasCount * (total_nids * 4 + total_pivots * 2);

            for (int i = 0; i < total_nids; i++) {
                stubBase.add(i * 4);
                placeDataType(program, stubBase, PointerDataType.dataType);
            }

            if (numFuncs > 0) {
                addLabel(program, nids_base, module_name + "_func_nids", true, false);
                placeDataType(program, nids_base, new ArrayDataType(UnsignedIntegerDataType.dataType, numFuncs, 4));
                addLabel(program, stubBase, module_name + "_funcs", true, false);
            }

            if (numVars > 0) {
                addLabel(program, nids_base.add(numFuncs * 4), module_name + "_var_nids", true, false);
                placeDataType(program, nids_base.add(numFuncs * 4), new ArrayDataType(UnsignedIntegerDataType.dataType, numVars, 4));
                addLabel(program, stubBase.add(numFuncs * 4), moduleName, true, false);
            }
            //
            // PIVOT TABLES
            // ------------------------
            tracker.sceResidentStart = tracker.sceResidentStart == null
                    ? nids_base
                    : (tracker.sceResidentStart.getOffset() > nids_base.getOffset()
                    ? nids_base
                    : tracker.sceResidentStart);
        }
    }

    public static Structure[] createModuleExportStructs(Program program) throws Exception {

        DataTypeManager dataTypeManager = program.getDataTypeManager();

        EnumDataType sceLibAttr = new EnumDataType(new CategoryPath("/PSP"), "SceLibAttr", 2);
        StructureDataType ent = new StructureDataType(new CategoryPath("/PSP"), "SceEntLibEntry", 0);

        sceLibAttr.add("NO_SPECIAL_ATTR", 0x0000, "The library has no special attributes");
        sceLibAttr.add("AUTO_EXPORT", 0x0001, "Automatically register the library to the system");
        sceLibAttr.add("WEAK_EXPORT", 0x0002, "Indicates resident library can be overwritten");
        sceLibAttr.add("NOLINK_EXPORT", 0x0004, "Indicates resident library is NOT being linked");
        sceLibAttr.add("WEAK_IMPORT", 0x0008, "Load module that references this library even if this library is not registered");
        sceLibAttr.add("SYSCALL_EXPORT", 0x4000, "Indicates the use of the SYSCALL technique for linking");
        sceLibAttr.add("SCE_LIB_IS_SYSLIB", 0x8000, "The library is a system library");

        dataTypeManager.addDataType(sceLibAttr, DataTypeConflictHandler.DEFAULT_HANDLER);

        ent.add(new PointerDataType(CharDataType.dataType), "libname", null);
        ent.add(new ArrayDataType(ByteDataType.dataType, 2, 1), "version", null);
        ent.add(sceLibAttr, "attribute", null);
        ent.add(ByteDataType.dataType, "size", null);
        ent.add(ByteDataType.dataType, "num_vars", null);
        ent.add(UnsignedShortDataType.dataType, "num_funcs", null);
        ent.add(new PointerDataType(VoidDataType.dataType), "resident_ptr", null);

        Structure dt1 = (Structure) dataTypeManager.addDataType(ent, DataTypeConflictHandler.DEFAULT_HANDLER);

        ent.setName("SceEntLibEntryEx");
        ent.setPackingEnabled(true);
        ent.add(UnsignedShortDataType.dataType, "num_vars_2", null);
        ent.addBitField(ByteDataType.dataType, 4, "func_pivot_size", null);
        ent.addBitField(ByteDataType.dataType, 4, "var_pivot_size", null);
        ent.add(ByteDataType.dataType, "alias_set_count", null);

        Structure dt2 = (Structure) dataTypeManager.addDataType(ent, DataTypeConflictHandler.DEFAULT_HANDLER);

        return new Structure[]{dt1, dt2};
    }
}
