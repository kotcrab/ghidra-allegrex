package ghidra.program.emulation

import ghidra.pcode.emulate.Emulate
import ghidra.pcode.emulate.EmulateInstructionStateModifier
//import ghidra.pcode.emulate.callother.CountLeadingOnesOpBehavior
//import ghidra.pcode.emulate.callother.CountLeadingZerosOpBehavior

class AllegrexEmulateInstructionStateModifier(emu: Emulate) : EmulateInstructionStateModifier(emu) {
  init {
    // Refer to allegrex.sinc for additional PcodeOp that can be implemented
    // registerPcodeOpBehavior("countLeadingZeros", CountLeadingZerosOpBehavior())
    // registerPcodeOpBehavior("countLeadingOnes", CountLeadingOnesOpBehavior())
  }
}
