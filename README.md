ghidra-allegrex
===============

Ghidra processor module adding support for the Allegrex CPU used in the PlayStation Portable.

Features:
- PSP calling convention
- Processor type auto-detection for ELF files
- Support for PSP specific ELF relocation sections (type A and B)
  - Image rebase after loading is also supported
- Disassembly and decompilation of VFPU instructions (see limitations bellow)
- Scripts for importing and exporting PPSSPP `.sym` files (function labels)
- Ghidra Debugger integration for debugging games running in PPSSPP

### Installation

Download prebuilt package from the [Releases](https://github.com/kotcrab/ghidra-allegrex/releases) section.
After extracting copy the `Allegrex` directory into `GHIDRA_INSTALL_DIR/Ghidra/Processors`

### Usage

#### Games

Drag decrypted EBOOT in ELF/PRX format into Ghidra. It should get automatically detected 
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

Likewise, you can use `PpssppExportSymFile` to export your work as a `.sym` file which can be imported
into PPSSPP. Enter `0` when asked for offset if your image base is already  at `08804000`.
You need to do `Reset symbol table` before importing the file in PPSSPP.

#### Kernel modules

Since version 1.7 relocations found in kernel modules are supported. Usage is very similar as when
importing games though kernel modules are usually loaded starting from address `88000000`. Note that
for some files (e.g. `sysmem`, `loadcore`) you will need to click `Options...` during import and
select option to use `reboot.bin` type B relocation mapping.

#### Raw binaries

Raw binaries are also supported. In that case you will need to manually select Allegrex as the processor
and set image base.

#### Debugger

TODO

- Ghidra file should contain module name to enable automatic dynamic to static listing mapping
- Issues:
  - Target is already being recorded
  - Current frame's bank does not exist
  - Step out error is ignored
  - Can't trigger breakpoint hit events

### VFPU Limitations

- Decompilation support is rather basic, almost every operation is converted to a function call such as `vadd_q(...)`  
  - Semantics of `vpfxs`, `vpfxt` and `vpfxd` are not currently modeled
- Second operand of `vfim.s` will be shown as an integer, should be shown as a half float. Sleigh does not support float tokens.

### Building

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `./gradlew ghidraInstall` - build and install into Ghidra (warning: contents of `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex` will be deleted before installing)
- `./gradlew ghidraInstallThenRun` - run `ghidraInstall` task then start Ghidra, useful for development
- `./gradlew shadowJar` - create single library jar file with all external dependencies included

After running `./gradlew shadowJar` you can manually install extension by copying:
 - `build/libs/ghidra-allegrex-all.jar` file to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/lib/Allegrex.jar`
 - `data` and `ghidra_scripts` directories to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/`

Ghidra should automatically recompile Sleigh files when importing an executable, if not run:
```bash
/ghidra_10.x.x/support$ ./sleigh -a ../Ghidra/Processors/Allegrex/data/languages/
```

### License

Licensed under Apache License 2.0.

Derived from Ghidra MIPS module licensed under Apache License 2.0.

Type B relocation parsing based on [prxtool](https://github.com/pspdev/prxtool) licensed under AFL v2.0.
