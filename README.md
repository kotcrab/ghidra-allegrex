ghidra-allegrex
===============

Ghidra processor module adding support for the Allegrex CPU used in the PlayStation Portable.

Features:

- Support for PSP specific ELF relocation sections (type A and B).
  - Image rebase after loading is also supported.
- Support for Allegrex specific instructions.
- Processor type auto-detection for ELF files.
- PSP calling convention support.
- Disassembly and decompilation of VFPU instructions (see limitations below).
- Scripts for importing and exporting PPSSPP `.sym` files (function labels).
- Support for exporting kernel modules as object files.

## Installation

Download prebuilt package from the [Releases](https://github.com/kotcrab/ghidra-allegrex/releases/) section. Select release which matches
your Ghidra version. Then depending on the version you're installing:

### Version 19 or newer

In main Ghidra window:

1. Select `File -> Install Extensions`.
2. Press the green plus button.
3. Select downloaded ZIP.
4. Restart Ghidra.

### Version 18 or earlier

Extract downloaded ZIP. After extracting copy the `Allegrex` directory into `GHIDRA_INSTALL_DIR/Ghidra/Processors`.

## Usage

### Games

Drag decrypted EBOOT in ELF/PRX format into Ghidra. It should get automatically detected as `PSP Executable (ELF)`
/ `Allegrex`. Now is your chance to set initial base address by clicking `Options...` and changing `Image Base`. It's
recommend you set it to `08804000` to match the usual address where games are loaded.

After importing and opening the file you should do the auto analysis. Default options are fine.

#### Using PPSSPP .sym scripts

PPSSPP identifies many functions automatically, it's useful to get those into Ghidra after doing the initial analysis. Export
the `.sym` file from PPSSPP and in Ghidra run script
`PpssppImportSymFile`. Select the `.sym` file. Enter `0` when asked for offset if your image base is already at `08804000`.
It's usually fine to run this script after you've started renaming functions in the binary. The script by default skips
unknown names from PPSSPP so your work can only get overwritten if you've renamed one of the autodetected function.

Likewise, you can use `PpssppExportSymFile` to export your work as a `.sym` file which can be imported into PPSSPP. Enter `0`
when asked for offset if your image base is already at `08804000`. You need to do `Reset symbol table` before importing the
file in PPSSPP.

### Kernel modules

Usage is very similar as when importing games though kernel modules are usually loaded starting from address `88000000`.
Note that for some files (e.g. `sysmem`, `loadcore`) you will need to click `Options...` during import and select checkbox to
use `reboot.bin` type B relocation mapping.

#### Exporting relocatable kernel objects

Kernel modules can be exported as object files (`.o`), those files can be used as input for the linker.
To learn more about this feature see
[here](https://github.com/kotcrab/ghidra-allegrex/wiki/Exporting-relocatable-kernel-objects).

### Raw binaries

Raw binaries are also supported. In that case you will need to manually select Allegrex as the processor and set image base.

## VFPU and other limitations

- VFPU decompilation support is rather basic, almost every operation is converted to a function call such as `vadd_q(...)`.
  - Semantics of `vpfxs`, `vpfxt` and `vpfxd` are not currently modeled in the decompiler.
- Second operand of `vfim.s` will be shown as an integer, should be shown as a half float. Sleigh does not support float
  tokens.
- Changing image base after importing is not supported for relocatable object files (`.o`).
- For functions using 64-bit arguments you need to check "Use Custom Storage" and manually specify argument storage 
  (this is caused by a [Ghidra issue](https://github.com/NationalSecurityAgency/ghidra/issues/2762)).

## Building

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `./gradlew buildExtension` - build extension, this will create a zip file in the `dist` directory.

The following commands require `GHIDRA_USER_DIR` environment variable, it must be set to your Ghidra user
directory, for example: `C:\Users\<user>\AppData\Roaming\ghidra\ghidra_11.1_PUBLIC`.

- `./gradlew ghidraInstall` - build and install into Ghidra (contents of `$GHIDRA_USER_DIR/Extensions/ghidra-allegrex` will be overwritten).
- `./gradlew ghidraInstallThenRun` - run `ghidraInstall` task then start Ghidra, useful for development.
- `./gradlew ghidraInstallThenDebug` - run `ghidraInstall` task then start Ghidra in debug mode, useful for development.

## License

Licensed under Apache License 2.0.

Derived from Ghidra MIPS module licensed under Apache License 2.0.

Type B relocation parsing based on [prxtool](https://github.com/pspdev/prxtool) licensed under AFL v2.0.

## See also

- [PSP RE quick start guide](https://psp-re.github.io/quickstart/) - Short guide that will present you all the necessary resources you need to start reverse engineering on PSP.
- [psp-ghidra-scripts](https://github.com/pspdev/psp-ghidra-scripts) - A collection of scripts to aid in reverse engineering PSP binaries in Ghidra.
