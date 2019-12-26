# Imports function labels from PPSSPP .sym file.
#@author Kotcrab
#@category Data

sym = askFile("Select PPSSPP .sym file", "Select")
offsetBy = askInt("Offset addresses by", "Offset")
skipZun = True
makePrimary = True

for line in file(sym.absolutePath):
    parts = line.split(" ")
    address = toAddr(long(parts[0], 16) + offsetBy)
    name = parts[1].rsplit(",", 1)[0]
    if skipZun and name.startswith("z_un_"):
        continue
    print "Create label", name, "at", address
    createLabel(address, name, makePrimary)
