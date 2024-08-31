package allegrex.program.emulation

import ghidra.pcode.emulate.Emulate
import ghidra.pcode.emulate.EmulateInstructionStateModifier

class AllegrexEmulateInstructionStateModifier(emu: Emulate) : EmulateInstructionStateModifier(emu) {
  init {
    // Refer to allegrex.sinc for additional PcodeOp that can be implemented
  }
}
