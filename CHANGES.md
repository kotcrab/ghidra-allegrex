#### Version: 1.8 (built with Ghidra 10.0.2)
- Improved disassembly of VFPU load and store instructions: register name and offset is now shown correctly
  - Warning: For existing projects you will need to clear the affected instructions and disassemble them again. Otherwise, you will see wrong disassembly
  - Hint: If the project was created before version 1.6 then you can spot wrongly disassembled instruction easily as they will have invalid references to `DAT` (e.g. `lv.q C000.q=>DAT_00000004,0x0(a0)`)  

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
