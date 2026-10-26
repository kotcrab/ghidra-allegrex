// Source-owned mtvc write-mask regression, independent of scalar vmtvc mapping.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VfpuMtvcMaskSmoke extends GhidraScript {
    private static final int[] SITES = {2, 5, 8, 11, 16};
    private static final long[] DESTINATIONS = {0x5300, 0x5308, 0x530c, 0x5320, 0x5314};
    private static final int[] EXPECTED_MASKS = {1, 1, 1, 1, 0};

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Not Allegrex");
        }
        Address start = currentProgram.getMinAddress();
        if (currentProgram.getMemory().getInt(start.add(8)) != 0x48e80080
                || currentProgram.getMemory().getInt(start.add(64)) != 0x48e80085) {
            throw new IllegalStateException("Fixture changed");
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble fixture");

        for (int i = 0; i < SITES.length; i++) {
            Instruction ins = currentProgram.getListing().getInstructionAt(start.add(SITES[i] * 4L));
            if (ins == null || !"mtvc".equals(ins.getMnemonicString())) {
                throw new IllegalStateException("Unexpected mtvc at word " + SITES[i]);
            }
            int maskedOperations = 0;
            int writes = 0;
            int forceOrs = 0;
            for (PcodeOp op : ins.getPcode()) {
                if (op.getOpcode() == PcodeOp.INT_AND) maskedOperations++;
                if (op.getOpcode() == PcodeOp.INT_OR) forceOrs++;
                if (op.getOutput() != null && op.getOutput().isRegister()
                        && op.getOutput().getOffset() == DESTINATIONS[i]) {
                    writes++;
                }
            }
            if (maskedOperations != EXPECTED_MASKS[i] || writes != EXPECTED_MASKS[i]
                    || forceOrs != (i == 3 ? 1 : 0)) {
                throw new IllegalStateException("Incorrect register mask/write at word " + SITES[i]
                        + ": AND=" + maskedOperations + " writes=" + writes + " OR=" + forceOrs);
            }
            println("VFPU_MTVC_MASK_PASS word=" + SITES[i]);
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            function = currentProgram.getFunctionManager().createFunction(
                    "vfpu_control_probe", start, new AddressSet(start, start.add(111)),
                    SourceType.USER_DEFINED);
        }
        if (function == null) throw new IllegalStateException("Cannot create fixture function");
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler not available");
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompiler did not complete");
            }
            String c = result.getDecompiledFunction().getC();
            println("VFPU_MTVC_C_START");
            println(c);
            println("VFPU_MTVC_C_END");
            Matcher match = Pattern.compile("(\\*param_1|param_1\\[([0-9]+)\\])\\s*=\\s*([^;]+);").matcher(c);
            Map<Integer, String> outputs = new HashMap<>();
            while (match.find()) {
                int index = match.group(2) == null ? 0 : Integer.parseInt(match.group(2));
                outputs.put(index, match.group(3).trim());
            }
            long[] expected = {0xfffffL, 0xfffL, 0x3fL, 0x3f8fffffL};
            for (int i = 0; i < expected.length; i++) {
                String expr = outputs.get(i);
                if (expr == null || Long.decode(expr) != expected[i]) {
                    throw new IllegalStateException("Unexpected decompiled value at " + i + ": " + expr);
                }
            }
            if (outputs.get(4) == null || !outputs.get(4).equals(outputs.get(5))) {
                throw new IllegalStateException("Read-only RSV5 changed in decompiled output: " + outputs);
            }
            println("VFPU_MTVC_DECOMP_PASS masked_constants=4 readonly_preserved=true");
        } finally {
            decompiler.dispose();
        }
        println("VFPU_MTVC_MASK_COMPLETE");
    }
}
