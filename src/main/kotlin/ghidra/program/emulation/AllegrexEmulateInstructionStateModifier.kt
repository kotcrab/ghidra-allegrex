package ghidra.program.emulation

import ghidra.pcode.emulate.Emulate
import ghidra.pcode.emulate.EmulateInstructionStateModifier
import ghidra.pcode.emulate.callother.CountLeadingOnesOpBehavior
import ghidra.pcode.emulate.callother.CountLeadingZerosOpBehavior

class AllegrexEmulateInstructionStateModifier(emu: Emulate) : EmulateInstructionStateModifier(emu) {
    init {
        registerPcodeOpBehavior("countLeadingZeros", CountLeadingZerosOpBehavior())
        registerPcodeOpBehavior("countLeadingOnes", CountLeadingOnesOpBehavior())

        //We could registerPcodeOpBehavior for one or more of the following pcodeop's:
        //break;
        //trap;
        //wait;
        //syscall;
        //cacheOp;
        //signalDebugBreakpointException;
        //disableInterrupts;
        //enableInterrupts;
        //hazzard;
        //lockload;
        //lockwrite;
        //synch;
        //tlbop;
        //bitSwap;
        //disableProcessor;
        //enableProcessor;
        //signalReservedInstruction;
        //prefetch;
        //getFpCondition;
        //getCopCondition;
        //setCopControlWord;
        //getCopControlWord;
        //copFunction;
        //getCopReg;
        //getCopRegH;
        //setCopReg;
        //setCopRegH;
        //extractField;
        //insertField;
        //getHWRegister;
        //setShadow;
        //getShadow;
        //special2;
        //SYNC;
        //TLB_invalidate;
        //TLB_invalidate_flush;
        //TLB_probe_for_matching_entry;
        //TLB_read_indexed_entryHi;
        //TLB_read_indexed_entryLo0;
        //TLB_read_indexed_entryLo1;
        //TLB_read_indexed_entryPageMask;
        //TLB_write_indexed_entry;
        //TLB_write_random_entry;
    }
}
