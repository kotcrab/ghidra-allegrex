package ghidra.app.util;

// Java depended
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.ArrayList;

// Ghidra depnd
import static ghidra.app.util.Utils.*;
import ghidra.app.util.Utils.FieldJson;
import ghidra.app.util.Utils.EnumJson;
import ghidra.app.util.Utils.FunctionJson;
import ghidra.app.util.Utils.StructJson;
import ghidra.app.util.Utils.EnumValueJson;
import ghidra.app.util.Utils.ModuleJson;
import ghidra.app.util.Utils.TypedefJson;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.data.ParameterDefinitionImpl;


public class ModuleType {


    private Program program;
    private DataTypeManager dtm;
    private Gson gson;

    public ModuleType (Program program) {
        this.program = program;
        this.dtm = program.getDataTypeManager();
        this.gson = new Gson();
    }

    public void createModule(String moduleName) throws Exception {

        InputStream is = getClass().getResourceAsStream(
            "/NIDs/types/" + moduleName + ".json"
        );

        if (is == null) {
            //throw new RuntimeException("JSON not found for module: " + moduleName);
            return;
        }

        Reader reader = new InputStreamReader(is);
        ModuleJson module = gson.fromJson(reader, ModuleJson.class);

        createTypedefs(module);
        createEnums(module);
        createStructs(module);
    }
    private void createEnums(ModuleJson module) {

    if (module.enums == null) return;

    CategoryPath path = new CategoryPath(module.category);

    for (EnumJson en : module.enums) {

        EnumDataType enumDt = new EnumDataType(path, en.name, en.size);

        for (EnumValueJson val : en.values) {
            enumDt.add(val.name, val.value);
        }

        dtm.addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
    }
}
private void createTypedefs(ModuleJson module) {
    if (module.typedefs == null) return;

    CategoryPath path = new CategoryPath(module.category);

    for (TypedefJson td : module.typedefs) {
        DataType baseType = resolveType(program, td.baseType);

        if (baseType != null) {
            TypedefDataType typedefDt = new TypedefDataType(path, td.name, baseType);
            dtm.addDataType(typedefDt, DataTypeConflictHandler.REPLACE_HANDLER);
        } else {
            ghidra.util.Msg.warn(this, "Não foi possível resolver o tipo base para o typedef: " + td.name);
        }
    }
}
private void createStructs(ModuleJson module) {

    if (module.structs == null) return;

    CategoryPath path = new CategoryPath(module.category);

    for (StructJson st : module.structs) {

        StructureDataType struct = new StructureDataType(path, st.name, 0);

        for (FieldJson field : st.fields) {

            DataType fieldType = resolveType(program, field.type);

            if (fieldType == null) continue;

            struct.add(fieldType, field.name, null);
        }

        dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }
}
public void applyFunctionSignature(String moduleName, String hexNID, Function f) throws Exception {
    InputStream is = getClass().getResourceAsStream("/NIDs/types/" + moduleName + ".json");
    if (is == null || f == null) return;

    ModuleJson module = gson.fromJson(new InputStreamReader(is), ModuleJson.class);
    if (module.functions == null) return;

    for (FunctionJson fj : module.functions) {
        if (fj.NID != null && fj.NID.equalsIgnoreCase(hexNID)) {
            DataType returnType = resolveType(program, fj.returnType != null ? fj.returnType : "void");
            
            ArrayList<ParameterImpl> params = new ArrayList<>();
            if (fj.values != null) {
                for (FieldJson paramJson : fj.values) {
                    DataType pType = resolveType(program, paramJson.type);
                    if (pType == null) pType = DataType.DEFAULT; // fallback

                    params.add(new ParameterImpl(paramJson.name, pType, program));
                }
            }

            f.updateFunction(null, new ParameterImpl(null, returnType, program), params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
            
            f.setName(fj.name, SourceType.USER_DEFINED);
            break; 
        }
    }
}


}

