package ghidra.app.plugin.core.analysis;

import  ghidra.app.util.ModuleType;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
//import ghidra.app.services.AnalyzerOptions;
import ghidra.framework.options.Options;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.FlowType;
import allegrex.analysis.RecoverSections;

@SuppressWarnings("unused")
public class AllegrexPspAnalyzer extends AbstractAnalyzer {
	private boolean doSectionRecovery = false;
  private boolean pspResolveNIDs = false;
	
	private static final String NAME = "PSP Analyzer (Allegrex)";
	private static final String DESCRIPTION = "Analyze PSP";
  private static final String OPTION_RECOVER = "Recover Sections (Exports, Imports, lib stub, rodata sceModuleInfo, etc)";
  private static final String OPTION_NIDS = "Resolver NIDs";

  public AllegrexPspAnalyzer () {
    super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
  }
  
  @Override
  public void registerOptions(Options options, Program program){
	      super.registerOptions(options, program);
        options.registerOption(OPTION_RECOVER, doSectionRecovery, null, "Recover PSP sections");
        options.registerOption(OPTION_NIDS, doSectionRecovery, null, "Resolver PSP NIDs");
  }
  
  @Override
  public void optionsChanged(Options options, Program program){
	      super.optionsChanged(options, program);
        doSectionRecovery = options.getBoolean(OPTION_RECOVER, doSectionRecovery);
        pspResolveNIDs = options.getBoolean(OPTION_NIDS, pspResolveNIDs);
  }
  
  @Override
  public boolean canAnalyze(Program program){
    return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Allegrex"));
  }
  
    @Override
  public boolean added (Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
    throws CancelledException {

      if (doSectionRecovery == true) {
        try {
            RecoverSections.RecoverSections(program, pspResolveNIDs);
        } catch (Exception e) {
            //log.appendMsg("Erro na recuperação de seções: " + e.getMessage());
            log.appendException(e);
            return false; 
        }
    }

		return true;
	}
}
