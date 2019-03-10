ghidra-allegrex
===============

Ghidra processor module adding support for Allegrex CPU used in the PlayStation Portable.

Derived from the built-in MIPS module.

Implemented:
- PSP calling convention
- Processor type auto detection for ELF files

To be done:
- Support for PSP specific ELF relocation section
- Clean up instructions and add PSP specific ones
- Support for VFPU
- Detecting common syscalls

#### Installation

1. Download zip or clone this repository and copy `Allegrex` directory to `install_dir/Ghidra/Processors`

2. For now you also have to copy `MIPS.jar` from `install_dir/Ghidra/Processors/MIPS/lib` 
to `install_dir/Ghidra/Processors/Allegrex/lib`
