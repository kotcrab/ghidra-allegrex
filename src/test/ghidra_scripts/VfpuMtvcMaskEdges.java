// Check mtvc control masks for boundary registers and ignored writes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class VfpuMtvcMaskEdges extends GhidraScript {
    private static final int[] WORDS = {
        0x48e80081, 0x48e80084, 0x48e80086, 0x48e80087,
        0x48e8008f, 0x48e80090, 0x48e800ff
    };
    private static final String[] DISPLAY = {
        "TPFX", "INF4", "RSV6", "REV", "RCX7", "S400", "(interlock)"
    };
    private static final int[] MASKED = {1, 0, 0, 0, 1, 0, 0};
    private static final int[] WRITES = {1, 1, 0, 0, 1, 0, 0};

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Not Allegrex");
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(4L * i)) != WORDS[i]) {
                throw new IllegalStateException("mtvc edge fixture changed at " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Could not disassemble mtvc edge fixture");

        for (int i = 0; i < WORDS.length; i++) {
            Instruction ins = currentProgram.getListing().getInstructionAt(start.add(4L * i));
            if (ins == null || !"mtvc".equals(ins.getMnemonicString())
                    || !ins.toString().contains(DISPLAY[i])) {
                throw new IllegalStateException("Unexpected mtvc display at " + i + ": " + ins);
            }
            int masks = 0, writes = 0, setBits = 0;
            for (PcodeOp op : ins.getPcode()) {
                if (op.getOpcode() == PcodeOp.INT_AND) masks++;
                if (op.getOpcode() == PcodeOp.INT_OR) setBits++;
                if (op.getOutput() != null && op.getOutput().isRegister()) writes++;
            }
            if (masks != MASKED[i] || writes != WRITES[i] || setBits != (i == 4 ? 1 : 0)) {
                throw new IllegalStateException("Incorrect mtvc edge semantics at " + i
                        + ": masks=" + masks + ", writes=" + writes + ", forcedBits=" + setBits);
            }
            println("VFPU_MTVC_EDGE_PASS index=" + i + " register=" + DISPLAY[i]);
        }
        println("VFPU_MTVC_EDGES_COMPLETE");
    }
}
