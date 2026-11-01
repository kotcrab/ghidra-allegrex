// Reproduces scalar/control operand mapping on real Ghidra, including invalid selectors.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class VfpuControlMappingSmoke extends GhidraScript {
    private static final int[] WORDS = {
        0x340800e4, 0x48e80000, 0xd0510001, 0x34080001,
        0x48e80000, 0xd0500100, 0x48690000, 0xac890000,
        0xd0501000, 0x48690000, 0xac890004, 0xd0507f00,
        0x48690000, 0xac890008, 0x03e00008, 0x00000000
    };

    private void verify(Address start, int index, String mnemonic, String name,
                        long dest, long source, boolean constant) throws Exception {
        Instruction ins = currentProgram.getListing().getInstructionAt(start.add(4L * index));
        if (ins == null || !mnemonic.equals(ins.getMnemonicString())
                || !ins.toString().contains(name)) {
            throw new IllegalStateException("Incorrect control decoding at " + index + ": " + ins);
        }
        int matched = 0;
        for (PcodeOp op : ins.getPcode()) {
            if (op.getOpcode() != PcodeOp.COPY || op.getOutput() == null
                    || !op.getOutput().isRegister()
                    || op.getOutput().getOffset() != dest) continue;
            Varnode in = op.getInput(0);
            if (constant && in.isConstant() && in.getOffset() == source
                    || !constant && in.isRegister() && in.getOffset() == source) matched++;
        }
        if (matched != 1) throw new IllegalStateException("Incorrect p-code at " + index);
        println("VFPU_CTRL_MAPPING_PASS " + mnemonic + " " + name);
    }

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Unexpected language");
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(4L * i)) != WORDS[i]) {
                throw new IllegalStateException("Fixture word changed at index " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Cannot disassemble fixture");
        verify(start, 2, "vmtvc", "S000,TPFX", 0x5304, 0x5000, false);
        verify(start, 5, "vmfvc", "S000,TPFX", 0x5000, 0x5304, false);
        verify(start, 8, "vmfvc", "S000,S400", 0x5000, 0, true);
        verify(start, 11, "vmfvc", "(interlock)", 0x5000, 0, true);

        Function f = currentProgram.getFunctionManager().createFunction(
                "vfpu_control_mapping_probe", start,
                new AddressSet(start, start.add(WORDS.length * 4L - 1)), SourceType.USER_DEFINED);
        if (f == null) throw new IllegalStateException("Unable to create probe function");
        DecompInterface d = new DecompInterface();
        try {
            if (!d.openProgram(currentProgram)) throw new IllegalStateException("Decompiler unavailable");
            DecompileResults result = d.decompileFunction(f, 30, monitor);
            if (result == null || !result.decompileCompleted()
                    || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompiler failed");
            }
            String c = result.getDecompiledFunction().getC();
            println("VFPU_CTRL_MAPPING_C_START");
            println(c);
            println("VFPU_CTRL_MAPPING_C_END");
            if (!c.contains("*param_1 = 0xe4;") || !c.contains("param_1[1] = 0;")
                    || !c.contains("param_1[2] = 0;")) {
                throw new IllegalStateException("Incorrect decompiled control readback");
            }
        } finally {
            d.dispose();
        }
        println("VFPU_CTRL_MAPPING_REVIEW_PASS");
    }
}
