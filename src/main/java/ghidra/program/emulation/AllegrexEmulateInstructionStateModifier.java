/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.emulation;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.CountLeadingOnesOpBehavior;
import ghidra.pcode.emulate.callother.CountLeadingZerosOpBehavior;
//import ghidra.pcode.emulate.callother.SignalingNaNOpBehavior;

public class AllegrexEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	public AllegrexEmulateInstructionStateModifier (Emulate emu) {
		super(emu);



		// These classes are defined here:
		// ghidra.git/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/pcode/emulate/callother

		registerPcodeOpBehavior("countLeadingZeros", new CountLeadingZerosOpBehavior());

		registerPcodeOpBehavior("countLeadingOnes", new CountLeadingOnesOpBehavior());

		/**
		 * We could registerPcodeOpBehavior for one or more of the following pcodeop's:
		 *
		 break;
		 trap;
		 wait;
		 syscall;
		 cacheOp;
		 signalDebugBreakpointException;
		 disableInterrupts;
		 enableInterrupts;
		 hazzard;
		 lockload;
		 lockwrite;
		 synch;
		 tlbop;
		 bitSwap;
		 disableProcessor;
		 enableProcessor;
		 signalReservedInstruction;
		 prefetch;
		 getFpCondition;
		 getCopCondition;
		 setCopControlWord;
		 getCopControlWord;
		 copFunction;
		 getCopReg;
		 getCopRegH;
		 setCopReg;
		 setCopRegH;
		 extractField;
		 insertField;
		 getHWRegister;
		 setShadow;
		 getShadow;
		 special2;
		 SYNC;
		 TLB_invalidate;
		 TLB_invalidate_flush;
		 TLB_probe_for_matching_entry;
		 TLB_read_indexed_entryHi;
		 TLB_read_indexed_entryLo0;
		 TLB_read_indexed_entryLo1;
		 TLB_read_indexed_entryPageMask;
		 TLB_write_indexed_entry;
		 TLB_write_random_entry;
		 *
		 */
	}
}
