# Imports function labels from PPSSPP .sym file.
# @author Kotcrab
# @category Data

sym = askFile("Select PPSSPP .sym file", "Select")
offsetBy = askInt("Offset addresses by", "Offset")
skipZun = True
makePrimary = True

with open(sym.absolutePath, "r") as f:
  for line in f:
    parts = line.split(" ")
    address = toAddr(int(parts[0], 16) + offsetBy)
    name = parts[1].rsplit(",", 1)[0]
    if skipZun and name.startswith("z_un_"):
      continue
    print("Create label", name, "at", address)
    createLabel(address, name, makePrimary)
