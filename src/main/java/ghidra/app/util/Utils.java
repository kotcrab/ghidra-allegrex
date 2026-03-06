package ghidra.app.util;

// Ghidra depredenc
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

// Java depedenc
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.ArrayList;

public class Utils {

    public static String getCString(Program program, Address addr) {
        if (addr == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        Memory mem = program.getMemory();

        try {
            while (true) {
                byte b = mem.getByte(addr);
                if (b == 0) {
                    break;
                }
                sb.append((char) b);
                addr = addr.add(1);
            }
        } catch (Exception e) {
            return "";
        }

        return sb.toString();
    }
        public static void placeDataType(Program program, Address addr, DataType dataType, int size) throws CodeUnitInsertionException, InvalidInputException {
        Listing listing = program.getListing();
        if (size == -1) {
            int dtSize = dataType.getLength() - 1;
            listing.clearCodeUnits(addr, addr.add(dtSize), false);
        } else {
            listing.clearCodeUnits(addr, addr.add(size - 1), false);
        }
        listing.createData(addr, dataType);
    }
        public static void createMemBlock(Program program, Address addr, int size, String name, boolean r, boolean w, boolean x) throws Exception {
        Memory memory = program.getMemory();
        MemoryBlock blkBefore = memory.getBlock(addr);
        MemoryBlock blk;

        if (blkBefore != null && blkBefore.getStart().equals(addr)) {
            Address addrNext = addr.add(size);
            MemoryBlock blkNext = memory.getBlock(addrNext);

            blkBefore.setName(name);
            if (blkNext != null && !blkNext.getStart().equals(addrNext)) {
                memory.split(blkNext, addrNext);
            }
		} else if (blkBefore != null) {
            memory.split(blkBefore, addr);
            blk = memory.getBlock(addr);
            if (blk != null) {
                try {
                    memory.split(blk, addr.add(size));
                } catch (MemoryAccessException e) {
                }
                blk.setName(name);
                blk.setRead(r);
                blk.setWrite(w);
                blk.setExecute(x);
            }

        }

    }
        public static String getNameForNID(String moduleName, String HexNid) {
        Gson gson = new Gson();
        InputStream is = Utils.class.getResourceAsStream(
            "/NIDs/types/" + moduleName + ".json"
        );

        if (is == null) {
            return moduleName + HexNid;
        }

        Reader reader = new InputStreamReader(is);
        ModuleJson module = gson.fromJson(reader, ModuleJson.class);

        for (FunctionJson fj : module.functions) {
            if (fj.NID != null && fj.NID.equalsIgnoreCase(HexNid)) {
                return fj.name;
            }
        }

        return moduleName + HexNid;
    }
    public static void placeDataType(Program program, Address addr, DataType dataType) throws CodeUnitInsertionException, InvalidInputException {
        Listing listing = program.getListing();
        int dtSize = dataType.getLength() - 1;
        listing.clearCodeUnits(addr, addr.add(dtSize), false);
        listing.createData(addr, dataType);
    }
    public static void addLabel(Program program, Address addr, String name, boolean makePrimary, boolean makeExternal) throws Exception {
        SymbolTable symbTbl = program.getSymbolTable();
        symbTbl.createLabel(addr, name, SourceType.USER_DEFINED);
        if (makeExternal) {
            makeExternal(addr, symbTbl);
        }
    }

    public static void makeExternal(Address addr, SymbolTable symbTbl) throws Exception {
        symbTbl.addExternalEntryPoint(addr);
    }

    public static Address toAddr(Program program, long value) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    public static DataType getDataTypeFromString2(Program program, String typeName) {

    java.util.List<DataType> foundTypes = new java.util.ArrayList<>();
    program.getDataTypeManager().findDataTypes(typeName, foundTypes);

    if (!foundTypes.isEmpty()) return foundTypes.get(0);

    DataTypeManager builtInMgr = BuiltInDataTypeManager.getDataTypeManager();
    builtInMgr.findDataTypes(typeName, foundTypes);

    if (!foundTypes.isEmpty()) return program.getDataTypeManager().resolve(foundTypes.get(0), DataTypeConflictHandler.DEFAULT_HANDLER);

    return null;
}
public static DataType getDataTypeFromString(Program program, String typeName) {
        DataTypeManager dtm = program.getDataTypeManager();
        List<DataType> foundTypes = new ArrayList<>();
        
        dtm.findDataTypes(typeName, foundTypes);
        if (!foundTypes.isEmpty()) return foundTypes.get(0);

        DataTypeManager builtinMgr = BuiltInDataTypeManager.getDataTypeManager();
        builtinMgr.findDataTypes(typeName, foundTypes);
        
        if (!foundTypes.isEmpty()) {
            return dtm.resolve(foundTypes.get(0), DataTypeConflictHandler.DEFAULT_HANDLER);
        }

        return null;
    }
public static DataType resolveType(Program program, String typeStr) {
        typeStr = typeStr.trim();

        if (typeStr.endsWith("*")) {
            String baseName = typeStr.substring(0, typeStr.length() - 1).trim();
            DataType base = resolveType(program, baseName);
            return (base != null) ? new PointerDataType(base) : new PointerDataType();
        }

        if (typeStr.contains("[") && typeStr.contains("]")) {
            int start = typeStr.indexOf("[");
            int end = typeStr.indexOf("]");
            String baseName = typeStr.substring(0, start).trim();
            int count = Integer.parseInt(typeStr.substring(start + 1, end));

            DataType base = resolveType(program, baseName);
            if (base == null) return null;
            return new ArrayDataType(base, count, base.getLength());
        }

        return getDataTypeFromString(program, typeStr);
    }
public static DataType resolveType2(Program program, String typeStr) {
    if (typeStr.endsWith("*")) {
        String baseName = typeStr.replace("*", "").trim();
        DataType base = getDataTypeFromString(program, baseName);
        if (base == null) return null;
        return new PointerDataType(base);
    }

    if (typeStr.contains("[")) {

        String baseName = typeStr.substring(0, typeStr.indexOf("["));
        int size = Integer.parseInt(
            typeStr.substring(typeStr.indexOf("[") + 1, typeStr.indexOf("]"))
        );

        DataType base = getDataTypeFromString(program, baseName);
        if (base == null) return null;

        return new ArrayDataType(base, size, base.getLength());
    }

    return getDataTypeFromString(program, typeStr);
}

    class ModuleJson {

        String module;
        String category;
        List<TypedefJson> typedefs;
        List<EnumJson> enums;
        List<StructJson> structs;
        List<FunctionJson> functions;
    }

    class FunctionJson {
    String name;
    String NID;
    List<FieldJson> values;
    String returnType; 
}

    class TypedefJson {
        String name;
        String baseType;
    }

    class EnumJson {
        String name;
        int size;
        boolean bitmask;
        List<EnumValueJson> values;
    }

    class EnumValueJson {
        String name;
        long value;
    }

    class StructJson {
        String name;
        List<FieldJson> fields;
    }

    class FieldJson {
        String name;
        String type;
    }
}
