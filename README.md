ghidra-allegrex
===============

Ghidra processor module adding support for the Allegrex CPU used in the PlayStation Portable.

Derived from the built-in MIPS module.

Implemented:
- PSP calling convention
- Processor type auto detection for ELF files
- Support for PSP specific ELF relocation section
  - Image rebase after loading is also supported
- Disassembly of VFPU instructions (see limitations bellow)
- Script for importing PPSSPP `.sym` files (importing function labels)

To be done:
- Exporting `.sym` files for PPSSPP

Future ideas:
- Integration with PPSSPP debugger

### Installation

Prebuilt package will be provided after more features are implemented.

### VFPU Limitations

Modelling the VFPU in Sleigh was pretty tricky due to how the same registers get different names depending
on the instruction. There are few instructions I couldn't get quite right:
- Only disassembly is possible with current implementation, decompiler won't be implemented.
- All VFPU memory load and stores (`lv.s`, `lv.q`, `lvl.q` etc.): name of VFPU register is not shown, only register number is visible.
This is because the VFPU register id is not continuous bitrange in the instruction. Additionally the memory offset should be signed short
but Ghidra shows it as unsigned value.
- First operand of `vpfxs`, `vpfxt` and `vpfxd` won't be decoded, requires too complex logic.
- Last operand of `vrot.s`, `vrot.p`, `vrot.t` and `vrot.q` won't be decoded, requires too complex logic.
- Second operand of `vfim.s` will be shown as integer, should be float. Sleigh does not support float tokens.

### Building

Note this project is still work in progress and breaking changes are likely.

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `gradle ghidraInstall` - build and install into Ghidra (warning: contents of `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex` will be deleted before installing)
- `gradle shadowJar` - create single library jar file with all external dependencies included

After `gradle shadowJar` you can manually install extension by copying:
 - `build/libs/ghidra-allegrex-all.jar` file to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/lib/Allegrex.jar`
 - `data` and `ghidra_scripts` directories to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/`

Ghidra should automatically recompile Sleigh files when importing an executable, if not run:
```bash
/ghidra_9.x.x/support$ ./sleigh -a ../Ghidra/Processors/Allegrex/data/languages/
```
