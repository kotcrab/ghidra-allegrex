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
- Scripts for importing and exporting PPSSPP `.sym` files (function labels)

In progress:
- Integration with PPSSPP debugger (experimental early stage, not yet released)

### Installation

Download prebuilt package from the [Releases](https://github.com/kotcrab/ghidra-allegrex/releases) section.
After extracting copy the `Allegrex` directory into `GHIDRA_INSTALL_DIR/Ghidra/Processors`

### Usage

Drag decrypted EBOOT in ELF format into Ghidra. It should get automatically detected 
as `PSP Executable (ELF)` / `Allegrex`. Now is your chance to set initial base address by 
clicking `Options...` and changing `Image Base`. I highly recommend you set it to `08804000`. 
If you leave it at `0` Ghidra may create many useless labels and references it confuses 
as memory access. Rebasing the image later is possible but will not remove those labels.

After importing and opening the file you should do the auto analysis. Default options are fine.

#### Using PPSSPP .sym scripts

PPSSPP identifies many functions automatically, it's useful to get those into Ghidra
after doing the initial analysis. Export the `.sym` file from PPSSPP and in Ghidra run script
`PpssppImportSymFile`. Select the `.sym` file. Enter `0` when asked for offset if your image base is already 
at `08804000`.
It's usually fine to run this script after you've started renaming functions in the binary. The script by 
default skips unknown names from PPSSPP so your work can only get overwritten if you've renamed
one of the autodetected function.

Likewise, you can use `PpssppExportSymFile` to export your work as `.sym` file which can be imported
into PPSSPP. Enter `0` when asked for offset if your image base is already  at `08804000`.
You need to do `Reset symbol table` before importing the file in PPSSPP.

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

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `./gradlew ghidraInstall` - build and install into Ghidra (warning: contents of `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex` will be deleted before installing)
- `./gradlew shadowJar` - create single library jar file with all external dependencies included

After running `./gradlew shadowJar` you can manually install extension by copying:
 - `build/libs/ghidra-allegrex-all.jar` file to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/lib/Allegrex.jar`
 - `data` and `ghidra_scripts` directories to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/`

Ghidra should automatically recompile Sleigh files when importing an executable, if not run:
```bash
/ghidra_10.x.x/support$ ./sleigh -a ../Ghidra/Processors/Allegrex/data/languages/
```
