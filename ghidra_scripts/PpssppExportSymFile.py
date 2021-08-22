# Export function labels as a PPSSPP .sym file.
#@author Kotcrab
#@category Data

def export(outSymPath, offsetBy):
  functions = currentProgram.getFunctionManager().getFunctions(True)
  with open(outSymPath, 'w') as outFile:
    for func in functions:
      off = func.getEntryPoint().offset + offsetBy
      name = func.getSignature().getName()
      size = func.getBody().getFirstRange().getLength() # not ideal but should cover most cases
      outFile.write("%08X %s,%04X\n" % (off, name, size))

sym = askFile("Select output PPSSPP .sym file", "Select")
offsetBy = askInt("Offset addresses by", "Offset")

if sym.exists():
  overwrite = askYesNo("Warning", "File already exists, overwrite?")
  if overwrite:
    export(sym.absolutePath, offsetBy)
else:
  export(sym.absolutePath, offsetBy)
