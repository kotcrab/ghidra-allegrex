#### Version: 1.10 (built with Ghidra 10.0.4)
- Added missing implementation for `sync` and `wait` instructions
- [#17](https://github.com/kotcrab/ghidra-allegrex/issues/17) - Added workaround for missing symbol sections when applying relocations

#### Version: 1.9 (built with Ghidra 10.0.4)
- Ghidra Debugger can be used to debug games running in PPSSPP
- Fixed decompilation of `max` and `min`
- From now on, the release zip will contain precompiled Allegrex Sleigh spec

#### Version: 1.8 (built with Ghidra 10.0.4)
- Updated to Ghidra 10.0.4
- Added initial support for decompiling VFPU instructions
  - **Warning**: For existing projects every VFPU branch instruction (`bvf`, `bvfl`, `bvt`, `bvtl`) must be cleared and disassembled again 
    to generate proper pcode
- Improved disassembly of VFPU instructions
  - **Warning**: For existing projects you will need to clear the affected instructions and disassemble them again. Otherwise,
    you will see wrong disassembly and decompilation
    - Hint: You can search bookmarks for "Instruction pcode is unimplemented" to find VFPU instructions.
    - Hint: If the project was disassembled before version 1.6 then you can easily spot wrongly disassembled load and store instruction as
      they will have invalid references to `DAT` (e.g. `lv.q C000=>DAT_00000004,0x0(a0)`).
    - Hint: To clear entire function: press `Select -> Function` then press `C` key to clear and `D` to dissemble again
    - Note: It should be possible to write a script that automatically clears and dissembles every affected function, such script might be
    provided in future versions
  - All VFPU load and store instructions: register name and offset is now shown correctly
  - Operands of `vpfxs`, `vpfxt` and `vpfxd` are now disassembled
  - Operands of all `vrot` instructions are now disassembled
  - Fixed wrong conditions and operands of `vmfvc` and `vmtvc`
  - Fixed wrong vector size of first operand of `vcst`
  - Fixed the mnemonic of `vwbn`
- Removed type suffixes for VFPU registers in disassembly

#### Version: 1.7 (built with Ghidra 10.0.2)
- Fixed decompilation of `ins`
- [#7](https://github.com/kotcrab/ghidra-allegrex/issues/7) - Added support for type B relocations (found in kernel modules)
  - This also adds new option during import to use alternative relocation mapping (must be checked for some files)

#### Version: 1.6 (built with Ghidra 10.0.2)
- Fixed VFPU load and store instructions creating references to DAT instead of just showing register number

#### Version: 1.5 (built with Ghidra 10.0.2)
- [#9](https://github.com/kotcrab/ghidra-allegrex/issues/9) - Fixed issues with loading binaries with debug symbols

#### Version: 1.4 (built with Ghidra 10.0.2)
- Added `PpssppExportSymFile` script

#### Version: 1.3 (built with Ghidra 10.0.2)
- Updated to Ghidra 10.0.2
- [#2](https://github.com/kotcrab/ghidra-allegrex/issues/2) - Fixed wrong endianness for `long long` return values

#### Version: 1.2 (built with Ghidra 9.2.1)
- Updated to Ghidra 9.2.1

#### Version: 1.1 (built with Ghidra 9.1.2)
- [#6](https://github.com/kotcrab/ghidra-allegrex/issues/6) - Rebasing image after importing can fail
  - Note: This fix will only apply to new projects

#### Version: 1.0 (built with Ghidra 9.1.2)
- [#5](https://github.com/kotcrab/ghidra-allegrex/pull/5) - Added bitrev, mfic, mtic, and wsbw instructions
- [#4](https://github.com/kotcrab/ghidra-allegrex/pull/4) - Added Coprocessor 0 registers and transfers

#### Version: 0.9
- Initial release
