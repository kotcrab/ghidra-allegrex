// Source-owned Ghidra p-code regression for Allegrex VFPU prefix instructions.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.HashMap;
import java.util.Map;

public class VfpuPrefixSmoke extends GhidraScript {
    private static final int[] WORDS = {
        0xdc0000c6, 0xdc0a35c6, 0xdd0756e4, 0xde0fffaa, 0xde000000
    };
    private static final long[] REGISTERS = {0x5300, 0x5300, 0x5304, 0x5308, 0x5308};
    private static final long[] VALUES = {0xc6, 0xa35c6, 0x756e4, 0xfaa, 0};
    private static final String[] MNEMONICS = {
        "vpfxs", "vpfxs", "vpfxt", "vpfxd", "vpfxd"
    };

    private Long value(Varnode input, Map<Long, Long> temporaries) {
        if (input.isConstant()) return input.getOffset();
        return input.isUnique() ? temporaries.get(input.getOffset()) : null;
    }

    @Override
    public void run() throws Exception {
        if (!"Allegrex:LE:32:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Expected the Allegrex language");
        }
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < WORDS.length; i++) {
            if (currentProgram.getMemory().getInt(start.add(i * 4L)) != WORDS[i]) {
                throw new IllegalStateException("Unexpected instruction bytes at index " + i);
            }
        }
        if (!disassemble(start)) throw new IllegalStateException("Disassembly failed");

        for (int i = 0; i < WORDS.length; i++) {
            Instruction instruction = currentProgram.getListing().getInstructionAt(start.add(i * 4L));
            if (instruction == null || !MNEMONICS[i].equals(instruction.getMnemonicString())) {
                throw new IllegalStateException("Unexpected instruction at index " + i + ": " + instruction);
            }
            Map<Long, Long> temporaries = new HashMap<>();
            Long written = null;
            for (PcodeOp op : instruction.getPcode()) {
                if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    throw new IllegalStateException("Opaque prefix operation at index " + i);
                }
                Varnode output = op.getOutput();
                if (output == null) continue;
                Long computed = null;
                if (op.getOpcode() == PcodeOp.COPY) {
                    computed = value(op.getInput(0), temporaries);
                } else if (op.getOpcode() == PcodeOp.INT_AND) {
                    Long left = value(op.getInput(0), temporaries);
                    Long right = value(op.getInput(1), temporaries);
                    if (left != null && right != null) computed = left & right;
                }
                if (computed == null) continue;
                if (output.isUnique()) temporaries.put(output.getOffset(), computed);
                if (output.isRegister() && output.getOffset() == REGISTERS[i]) written = computed;
            }
            if (written == null || written.longValue() != VALUES[i]) {
                throw new IllegalStateException("Wrong prefix value at " + i + ": " + written);
            }
            println("VFPU_PREFIX_PASS " + MNEMONICS[i] + " = 0x" + Long.toHexString(written));
        }
        println("VFPU_PREFIX_SMOKE_COMPLETE");
    }
}
