ghidra-allegrex
===============

Ghidra processor module adding support for the Allegrex CPU used in the PlayStation Portable.

Derived from the built-in MIPS module.

Implemented:
- PSP calling convention
- Processor type auto detection for ELF files
- Support for PSP specific ELF relocation section
  - Image rebase after loading should work too

To be done:
- Clean up instructions and add PSP specific ones
- Support for VFPU
- Detecting common syscalls (or importing / exporting `.sym` files from PPSSPP)

Future ideas:
- Integration with PPSSPP debugger

#### Installation

Prebuilt package will be provided after more features are implemented.

#### Building

`GHIDRA_HOME` environment variable must be set to Ghidra root installation directory.

Run `gradle shadowJar` and then copy:
 - `build/libs/ghidra-allegrex-all.jar` file to `GHIDRA_HOME/Ghidra/Processors/Allegrex/lib/Allegrex.jar`
 - `data` directory to `GHIDRA_HOME/Ghidra/Processors/Allegrex/`
