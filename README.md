ghidra-allegrex
===============

Ghidra processor module adding support for the Allegrex CPU used in the PlayStation Portable.

Derived from the built-in MIPS module.

Implemented:
- PSP calling convention
- Processor type auto detection for ELF files
- Support for PSP specific ELF relocation section
  - Image rebase after loading is also supported

To be done:
- Clean up instructions and add PSP specific ones
- Support for VFPU
- Detecting common syscalls (or importing / exporting `.sym` files from PPSSPP)

Future ideas:
- Integration with PPSSPP debugger

### Installation

Prebuilt package will be provided after more features are implemented.

### Building

Note this project is still work in progress and breaking changes are likely.

`GHIDRA_INSTALL_DIR` environment variable must be set to Ghidra root installation directory.

- `gradle ghidraInstall` - build and install into Ghidra (warning: contents of `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex` will be deleted before installing)
- `gradle shadowJar` - create single library jar file with all external dependencies included

After `gradle shadowJar` you can manually install extension by copying:
 - `build/libs/ghidra-allegrex-all.jar` file to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/lib/Allegrex.jar`
 - `data` directory to `GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex/`

Ghidra should automatically recompile Sleigh files when importing an executable, if not run:
```bash
/ghidra_9.x.x/support$ ./sleigh -a ../Ghidra/Processors/Allegrex/data/languages/
```
