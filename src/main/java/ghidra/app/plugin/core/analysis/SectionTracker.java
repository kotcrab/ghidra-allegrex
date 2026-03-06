// Recover some section names and apply NIDs for PSP binaries.
// Adapted from the original Python script by Ethanol.
// @author Ethanol (Original Script)
// @author SHADOW (Ghidra Java Implementation)
// @category Analysis

package allegrex.analysis;

// java
import java.util.ArrayList;
import java.util.List;

// Ghidra
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;

public class SectionTracker{
	final List<StubInfo> imports;
	Address sceResidentStart;
	int sceResidentSize;
	Address sceNidStart;
	int sceNidSize;
	final List<StubInfo> funcStubs;
	final List<StubInfo> varsStubs;
	
	public SectionTracker(){
		this.imports = new ArrayList<>();
		this.sceResidentStart = null;
		this.sceResidentSize = 0;
		this.sceNidStart = null;
		this.sceNidSize = 0;
		this.funcStubs = new ArrayList<>();
		this.varsStubs = new ArrayList<>();
	}
	public List<StubInfo> getImports(){
		return imports;
	}
	public Address getsceResidentStart(){
		return sceResidentStart;
	}
}
class StubInfo {
	String name;
	Address stubAddr;
	int sectionSize;
	
	public StubInfo(String modName, Address stubAddr, int sectionSize){
		this.name = modName;
		this.stubAddr = stubAddr;
		this.sectionSize = sectionSize;
	}
}