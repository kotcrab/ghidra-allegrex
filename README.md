ghidra-allegrex
===============

Ghidra processor module adding support for the Allegrex CPU used in the PlayStation Portable.

Derived from the built-in MIPS module.

Implemented:
- PSP calling convention
- Processor type auto detection for ELF files

To be done:
- Support for PSP specific ELF relocation section
- Clean up instructions and add PSP specific ones
- Support for VFPU
- Detecting common syscalls (or importing / exporting `.sym` files from PPSSPP)

Future ideas:
- Integration with PPSSPP debugger

#### Installation

Prebuilt package will be provided after more features are implemented
