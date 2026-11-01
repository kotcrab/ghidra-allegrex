// mtvc masks, ignored writes, and the resulting decompiled constants.
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
    private void check(Address start, int index, String name, long dest,
                       boolean masked, boolean forcedBits) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(start.add(4L * index));
        if (ins == null || !"mtvc".equals(ins.getMnemonicString())
                || !ins.toString().contains(name)) {
            throw new IllegalStateException("Unexpected mtvc at word " + index + ": " + ins);
        }
        int ands = 0, ors = 0, writes = 0;
        for (PcodeOp op : ins.getPcode()) {
            if (op.getOpcode() == PcodeOp.INT_AND) ands++;
            if (op.getOpcode() == PcodeOp.INT_OR) ors++;
            if (op.getOutput() != null && op.getOutput().isRegister()) {
                if (dest < 0 || op.getOutput().getOffset() != dest) {
                    throw new IllegalStateException("Unexpected control write at " + index + ": " + op);
                }
                writes++;
            }
        }
        if (ands != (masked ? 1 : 0) || ors != (forcedBits ? 1 : 0)
                || writes != (dest < 0 ? 0 : 1)) {
            throw new IllegalStateException("Wrong mtvc semantics at " + index);
        }
        println("VFPU_MTVC_PASS word=" + index + " register=" + name);
    }

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Expected Allegrex language");
        }
        Address start = currentProgram.getMinAddress();
        if (currentProgram.getMemory().getInt(start.add(8)) != 0x48e80080
                || currentProgram.getMemory().getInt(start.add(64)) != 0x48e80085) {
            throw new IllegalStateException("Original runtime fixture changed");
        }
        int[] edgeWords = {
            0x48e80081, 0x48e80084, 0x48e80086, 0x48e80087,
            0x48e8008f, 0x48e80090, 0x48e800ff
        };
        for (int i = 0; i < edgeWords.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(112L + 4L * i)) != edgeWords[i]) {
                throw new IllegalStateException("Selector fixture changed at " + i);
            }
        }
        if (!disassemble(start) || !disassemble(start.add(112))) {
            throw new IllegalStateException("Disassembly failed");
        }
        check(start, 2, "SPFX", 0x5300, true, false);
        check(start, 5, "DPFX", 0x5308, true, false);
        check(start, 8, "CC", 0x530c, true, false);
        check(start, 11, "RCX0", 0x5320, true, true);
        check(start, 16, "RSV5", -1, false, false);
        check(start, 28, "TPFX", 0x5304, true, false);
        check(start, 29, "INF4", 0x5310, false, false);
        check(start, 30, "RSV6", -1, false, false);
        check(start, 31, "REV", -1, false, false);
        check(start, 32, "RCX7", 0x533c, true, true);
        check(start, 33, "S400", -1, false, false);
        check(start, 34, "(interlock)", -1, false, false);

        Function function = currentProgram.getFunctionManager().createFunction(
                "vfpu_control_probe", start, new AddressSet(start, start.add(111)),
                SourceType.USER_DEFINED);
        if (function == null) throw new IllegalStateException("Cannot create fixture function");
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler unavailable");
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompilation failed");
            }
            String c = result.getDecompiledFunction().getC();
            println("VFPU_MTVC_C_START\n" + c + "\nVFPU_MTVC_C_END");
            Matcher match = Pattern.compile("(\\*param_1|param_1\\[([0-9]+)\\])\\s*=\\s*([^;]+);").matcher(c);
            Map<Integer, String> output = new HashMap<>();
            while (match.find()) {
                output.put(match.group(2) == null ? 0 : Integer.parseInt(match.group(2)),
                           match.group(3).trim());
            }
            long[] expected = {0xfffffL, 0xfffL, 0x3fL, 0x3f8fffffL};
            for (int i = 0; i < expected.length; i++) {
                String value = output.get(i);
                if (value == null || Long.decode(value) != expected[i]) {
                    throw new IllegalStateException("Wrong decompiled value at " + i + ": " + value);
                }
            }
            if (output.get(4) == null || !output.get(4).equals(output.get(5))) {
                throw new IllegalStateException("Read-only RSV5 value changed");
            }
        } finally {
            decompiler.dispose();
        }
        println("VFPU_MTVC_MASK_COMPLETE");
    }
}
