package allegrex.export

import allegrex.export.ExportElf.Const.SHF_ALLOC
import allegrex.export.ExportElf.Const.SHF_EXECINSTR
import allegrex.export.ExportElf.Const.SHF_INFO_LINK
import allegrex.export.ExportElf.Const.SHF_WRITE
import allegrex.export.ExportElf.Const.SHT_PROGBITS
import allegrex.export.ExportElf.Const.SHT_REL
import allegrex.export.ExportElf.Const.SHT_STRTAB
import allegrex.export.ExportElf.Const.SHT_SYMTAB
import allegrex.export.ExportElf.Const.STB_GLOBAL
import allegrex.export.ExportElf.Const.STB_LOCAL
import allegrex.export.ExportElf.Const.STB_WEAK
import allegrex.export.ExportElf.Const.STT_FUNC
import allegrex.export.ExportElf.Const.STT_NOTYPE
import allegrex.export.ExportElf.Const.STT_SECTION
import allegrex.export.ExportElf.SectionName.COMBINED_0
import allegrex.export.ExportElf.SectionName.COMBINED_1
import allegrex.export.ExportElf.SectionName.REL_COMBINED_0
import allegrex.export.ExportElf.SectionName.REL_COMBINED_1
import allegrex.export.ExportElf.SectionName.SHSTRTAB
import allegrex.export.ExportElf.SectionName.STRTAB
import allegrex.export.ExportElf.SectionName.SYMTAB
import allegrex.format.elf.relocation.AllegrexElfRelocationConstants
import allegrex.format.elf.relocation.AllegrexRelocation
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileResults
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.app.util.DomainObjectService
import ghidra.app.util.Option
import ghidra.app.util.OptionException
import ghidra.app.util.OptionUtils
import ghidra.app.util.exporter.Exporter
import ghidra.app.util.exporter.ExporterException
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.PcodeOpAST
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.reloc.Relocation
import ghidra.program.model.symbol.SymbolType
import ghidra.util.task.TaskMonitor
import java.io.File
import java.io.IOException

@Suppress("unused")
class RelocatableKernelObjectExporter : Exporter(
  "Relocatable PSP kernel object", "o", null
) {
  companion object {
    private object Options {
      object GlobalDataSymbolsPattern {
        private const val NAME = "Global data symbols names (regex)"
        const val DEFAULT = "^g_.+\$"

        fun toOption() = Option(NAME, DEFAULT)

        fun getValue(options: List<Option>): String = OptionUtils.getOption(NAME, options, DEFAULT)
      }
    }

    private val importStubBytes = byteArrayOf(0x08, 0x00, 0xe0.toByte(), 0x03, 0x00, 0x00, 0x00, 0x00) // jr ra / nop
    private val kernelRelocationsSectionTypeBytes = byteArrayOf(0xa1.toByte(), 0x00, 0x00, 0x70) // SHT_PSP_REL_TYPE_B

    // Section list for getting section indexes, they must appear in this order in output
    private val sectionNames = listOf(
      "", // UNDEF
      COMBINED_0,
      REL_COMBINED_0,
      COMBINED_1,
      REL_COMBINED_1,
      SYMTAB,
      STRTAB,
      SHSTRTAB,
    )
  }

  private var globalDataSymbolsRegex = Regex(Options.GlobalDataSymbolsPattern.DEFAULT)

  override fun getOptions(domainObjectService: DomainObjectService): List<Option> {
    return listOf(
      Options.GlobalDataSymbolsPattern.toOption(),
    )
  }

  @Throws(OptionException::class)
  override fun setOptions(options: List<Option>) {
    runCatching {
      globalDataSymbolsRegex = Regex(Options.GlobalDataSymbolsPattern.getValue(options))
    }
      .getOrElse { throw OptionException(it.message) }
  }

  override fun supportsAddressRestrictedExport(): Boolean {
    return false
  }

  @Throws(ExporterException::class, IOException::class)
  override fun export(file: File, domainObj: DomainObject, addrSet: AddressSetView?, monitor: TaskMonitor): Boolean {
    if (domainObj !is Program) {
      log.appendMsg("Unsupported type: " + domainObj.javaClass.name)
      return false
    }
    try {
      return exportProgram(file, domainObj, monitor)
    } catch (e: ProcessingException) {
      log.appendMsg("ERROR: ${e.message}")
      return false
    } catch (e: Exception) {
      throw ExporterException(e)
    }
  }

  private fun exportProgram(file: File, program: Program, monitor: TaskMonitor): Boolean {
    val validationMessage = validateKernelModule(program)
    if (validationMessage != null) {
      log.appendMsg("This file doesn't appear to be a PSP kernel module. $validationMessage")
      return false
    }
    validateListingInstructions(program)
    val memoryBlocks = resolveMemoryBlocks(program)
    val programBytes = memoryBlocks.map { block ->
      ByteArray(block.size.toInt())
        .also { block.getBytes(block.start, it) }
    }
    val resolvedLoRelocations = resolveHiLoRelocations(program, monitor)
    monitor.message = "Creating output file"
    unapplyRelocations(program, memoryBlocks, programBytes)
    val symbols = collectSymbols(program)
    val functions = collectFunctions(program)
    val strTab = ExportElf.StringAllocator()
    val elfSymbols = createElfSymbols(strTab, symbols, functions)
    validateElfSymbolsDuplicates(strTab, elfSymbols)
    val (shStrTab, elfSections) = createElfSections()
    val elfRelocations = createElfRelocations(program, symbols, programBytes, resolvedLoRelocations, strTab, elfSymbols)
    ExportElf.writeElf(file, elfSections, shStrTab, elfSymbols, strTab, programBytes, elfRelocations)
    return true
  }

  private fun validateKernelModule(program: Program): String? {
    val programHeaders = program.memory.getBlock("_elfProgramHeaders")
      ?: return "Section _elfProgramHeaders is missing"
    if (programHeaders.size != 0x20L * 3) {
      return "Program doesn't have 3 program headers"
    }
    val lastType = ByteArray(4)
      .also { programHeaders.getBytes(programHeaders.start.add(0x20L * 2), it) }
    if (!lastType.contentEquals(kernelRelocationsSectionTypeBytes)) {
      return "Kernel relocations program header not found as the last header"
    }
    return null
  }

  private fun validateListingInstructions(program: Program) {
    var missingInstructions = false
    program.relocationTable.relocations.asSequence()
      .filter { it.type == AllegrexElfRelocationConstants.R_MIPS_X_JAL26 }
      .forEach { relocation ->
        if (program.listing.getInstructionAt(relocation.address) == null) {
          log.appendMsg("Could not find instruction for JAL relocation at address ${relocation.address}, is the code disassembled there?")
          missingInstructions = true
        }
      }
    if (missingInstructions) {
      throw ProcessingException("Some instructions are not disassembled. Disassemble them before exporting.")
    }
  }

  private fun resolveMemoryBlocks(program: Program): List<MemoryBlock> {
    val firstBlock = program.memory.blocks.firstOrNull { it.start == program.imageBase }
      ?: throw ProcessingException("There must be memory block that start at image base")
    val secondBlock = program.memory.blocks.sortedBy { it.start }
      .firstOrNull { it.start > firstBlock.start }
      ?: throw ProcessingException("There must be memory block that starts after the first block")
    return listOf(firstBlock, secondBlock)
  }

  private fun resolveHiLoRelocations(program: Program, monitor: TaskMonitor): List<ResolvedLoRelocation> {
    val (loRelocations, hiRelocations) = program.relocationTable.relocations.asSequence()
      .filter { it.type == AllegrexElfRelocationConstants.R_MIPS_LO16 || it.type == AllegrexElfRelocationConstants.R_MIPS_X_HI16 }
      .partition { it.type == AllegrexElfRelocationConstants.R_MIPS_LO16 }

    val functions = getFunctionsForRelocationsOrThrow(program, loRelocations)
    val decompiledFunctions = decompileFunctions(program, functions, monitor)

    monitor.message = "Processing HI/LO relocations"
    val remainingHiRelocations = hiRelocations.toMutableList()
    val hiRelocationToTargetAddresses = mutableMapOf<Address, MutableSet<Int>>()
    val resolvedLoRelocations = loRelocations.map { loRelocation ->
      val (imageTargetAddress, sourceAddresses) = getHiLoRelocationTargetAndSourceAddresses(program, loRelocation, decompiledFunctions)
      val relatedHiRelocations = remainingHiRelocations
        .filter { it.address in sourceAddresses }
      remainingHiRelocations.removeAll(relatedHiRelocations)
      hiRelocations // To spot duplicates can't use relatedHiRelocations here
        .filter { it.address in sourceAddresses }
        .forEach { hiRelocation ->
          hiRelocationToTargetAddresses.getOrPut(hiRelocation.address) { mutableSetOf() }
            .add(imageTargetAddress)
        }

      ResolvedLoRelocation(
        loRelocation = loRelocation,
        relatedHiRelocations = relatedHiRelocations,
        targetAddress = imageTargetAddress - program.imageBase.offset.toInt()
      )
    }

    if (remainingHiRelocations.isNotEmpty()) {
      log.appendMsg("WARN: There are unaccounted HI relocations at addresses: ${remainingHiRelocations.map { it.address }}")
    }
    hiRelocationToTargetAddresses
      .filterValues { it.size > 1 }
      .forEach { (hiRelocationAddress, resolvedAddresses) ->
        log.appendMsg(
          "WARN: HI relocations at addresses $hiRelocationAddress resolved to multiple addresses: " +
            "${resolvedAddresses.map { Integer.toHexString(it) }}"
        )
      }

    return resolvedLoRelocations
  }

  private fun getFunctionsForRelocationsOrThrow(program: Program, relocations: List<Relocation>): List<Function> {
    var missingFunctions = false
    val functions = relocations.map { relocation ->
      program.functionManager.getFunctionContaining(relocation.address)
        .also {
          if (it == null) {
            log.appendMsg("Could not find function for HI relocation at address ${relocation.address}, is the function defined?")
            missingFunctions = true
          }
        }
    }
      .distinct()
    if (missingFunctions) {
      throw ProcessingException("Some functions containing HI relocations are not defined. Create them before exporting.")
    }
    return functions
  }

  private fun getHiLoRelocationTargetAndSourceAddresses(
    program: Program,
    loRelocation: Relocation,
    decompiledFunctions: Map<Function, DecompileResults>
  ): Pair<Int, Set<Address>> {
    val lowFunction = program.functionManager.getFunctionContaining(loRelocation.address)
    val highFunction = decompiledFunctions[lowFunction]?.highFunction
      ?: error("Missing decompilation result for relocation ${loRelocation.address}")
    val instruction = program.listing.getInstructionAtOrThrow(loRelocation.address)
    val lastLowPcode = instruction.pcode.lastOrNull {
      when (instruction.mnemonicString.removePrefix("_")) {
        "sb", "sh", "sc" -> it.opcode == PcodeOp.STORE
        "lb", "lbu", "lh", "lhu" -> it.opcode == PcodeOp.LOAD
        else -> true
      }
    } ?: throw ProcessingException("Could not find low pcode for instruction at ${loRelocation.address}")
    val highPcodeAddress = when {
      instruction.isInDelaySlot -> loRelocation.address.subtract(4)
      else -> loRelocation.address
    }
    val pcodeOps = highFunction.getPcodeOps(highPcodeAddress).asSequence().toList()
    val lastPcode = pcodeOps
      .lastOrNull { pcode -> pcode.opcode == lastLowPcode.opcode }
      ?: throw ProcessingException("Could not find high pcode for instruction at ${loRelocation.address}")

    val sourceAddresses = mutableSetOf<Address>()
    val imageTargetAddress = when (lastPcode.opcode) {
      PcodeOp.LOAD, PcodeOp.STORE -> backtraceVarnode(program, sourceAddresses, lastPcode.inputs[1])
      else -> backtrackPcode(program, sourceAddresses, lastPcode)
    }
    return imageTargetAddress to sourceAddresses
  }

  private fun backtrackPcode(program: Program, sourceAddresses: MutableSet<Address>, pcode: PcodeOpAST): Int {
    return when (pcode.opcode) {
      PcodeOp.INT_ADD -> backtraceVarnode(program, sourceAddresses, pcode.inputs[0]) + backtraceVarnode(program, sourceAddresses, pcode.inputs[1])
      PcodeOp.INT_SUB -> backtraceVarnode(program, sourceAddresses, pcode.inputs[0]) - backtraceVarnode(program, sourceAddresses, pcode.inputs[1])
      PcodeOp.INT_OR -> backtraceVarnode(program, sourceAddresses, pcode.inputs[0]) or backtraceVarnode(program, sourceAddresses, pcode.inputs[1])
      PcodeOp.INT_LEFT -> backtraceVarnode(program, sourceAddresses, pcode.inputs[0]) shl backtraceVarnode(program, sourceAddresses, pcode.inputs[1])
      PcodeOp.COPY, PcodeOp.INDIRECT -> backtraceVarnode(program, sourceAddresses, pcode.inputs[0])
      PcodeOp.MULTIEQUAL -> {
        val values = pcode.inputs
          .filter { it.def != pcode } // TODO Might not prevent all infinite recursion cases
          .map { backtraceVarnode(program, sourceAddresses, it) }.distinct()
        if (values.size > 1) {
          log.appendMsg("WARN: MULTIEQUAL pcode resolved to multiple different addresses, related addresses $sourceAddresses")
        }
        values.first()
      }
      else -> throw ProcessingException("Too complex data flow or unhandled pcode op ${pcode.opcode} in pcode: $pcode")
    }
  }

  private fun backtraceVarnode(program: Program, sourceAddresses: MutableSet<Address>, varnode: Varnode): Int {
    if (varnode.isConstant) {
      return varnode.offset.toInt()
    }
    val def = varnode.def
      ?: throw ProcessingException("Varnode $varnode is missing definition")
    val instruction = program.listing.getInstructionAtOrThrow(def.seqnum.target)
    if (instruction.delaySlotDepth > 0) {
      // this is a branch or jump instruction, the instruction which actually affects the relocation must be in the delay slot
      sourceAddresses.add(def.seqnum.target.add(4))
    } else {
      sourceAddresses.add(def.seqnum.target)
    }
    return backtrackPcode(program, sourceAddresses, def as PcodeOpAST)
  }

  private fun decompileFunctions(program: Program, functions: List<Function>, monitor: TaskMonitor): Map<Function, DecompileResults> {
    val decompiler = createDecompiler(program)
    val decompiledFunctions = try {
      functions.associateWith { function ->
        monitor.message = "Decompiling ${function.name}"
        decompiler.decompileFunction(function, decompiler.options.defaultTimeout, monitor).also {
          if (!it.decompileCompleted()) {
            throw ProcessingException("Failed to decompile ${function.name}")
          }
        }
      }
    } finally {
      decompiler.dispose()
    }
    return decompiledFunctions
  }

  private fun createDecompiler(program: Program): DecompInterface {
    val decompiler = DecompInterface()
    decompiler.setOptions(DecompilerUtils.getDecompileOptions(this.provider, program))
    decompiler.toggleCCode(false)
    decompiler.toggleSyntaxTree(true)
    decompiler.setSimplificationStyle("firstpass")
    decompiler.openProgram(program)
    return decompiler
  }

  private fun unapplyRelocations(program: Program, memoryBlocks: List<MemoryBlock>, programBytes: List<ByteArray>) {
    program.relocationTable.relocations.forEach { relocation ->
      val index = memoryBlocks.indexOfFirst { it.addressRange.contains(relocation.address) }
      if (index == -1) {
        throw ProcessingException("Could not find source memory block for relocation at ${relocation.address}")
      }
      val offset = relocation.address.subtract(memoryBlocks[index].start).toInt()
      System.arraycopy(relocation.bytes, 0, programBytes[index], offset, relocation.bytes.size)
    }
  }

  private fun collectSymbols(program: Program): List<ModuleSymbol> {
    return program.symbolTable.symbolIterator
      .filter { it.isPrimary }
      .mapNotNull map@{ symbol ->
        val dataType = program.listing.getDataAt(symbol.address)?.dataType
        ModuleSymbol(
          name = symbol.name,
          address = symbol.address.subtract(program.imageBase).toInt(),
          dataLength = (dataType?.length ?: -1).takeIf { it > 0 },
          global = symbol.name.matches(globalDataSymbolsRegex),
          data = symbol.symbolType == SymbolType.LABEL
        )
      }
  }

  private fun collectFunctions(program: Program): List<ModuleFunction> {
    val implementationTag = program.functionManager.functionTagManager.getFunctionTag("IMPLEMENTATION")
    return program.functionManager.getFunctions(true)
      .map {
        ModuleFunction(
          name = it.name,
          entryPoint = it.entryPoint.subtract(program.imageBase).toInt(),
          length = it.body.addressRanges.first().length.toInt(),
          import = !it.tags.contains(implementationTag) && isFunctionLikelyImport(program.memory, it)
        )
      }
  }

  private fun isFunctionLikelyImport(memory: Memory, function: Function): Boolean {
    val ranges = function.body.addressRanges.toList()
    return ranges.size == 1 && isRangeLikelyImportStub(memory, ranges.first())
  }

  private fun isRangeLikelyImportStub(memory: Memory, range: AddressRange): Boolean {
    val length = range.length.toInt()
    if (length != 8) {
      return false
    }
    val bytes = ByteArray(length)
      .also { memory.getBytes(range.minAddress, it) }
    return bytes.contentEquals(importStubBytes)
  }

  private fun createElfSymbols(
    strTab: ExportElf.StringAllocator,
    symbols: List<ModuleSymbol>,
    functions: List<ModuleFunction>
  ): List<ExportElf.Symbol> {
    val combinedSectionSymbols =
      listOf(
        ExportElf.Symbol(strTab.getOrPut(COMBINED_0), 0, 0, (STB_LOCAL or STT_SECTION).toByte(), 0, sectionNames.indexOf(COMBINED_0)),
        ExportElf.Symbol(strTab.getOrPut(COMBINED_1), 0, 0, (STB_LOCAL or STT_SECTION).toByte(), 0, sectionNames.indexOf(COMBINED_1)),
      )
    val weakFunctionSymbols = functions
      .filter { !it.import }
      .map {
        ExportElf.Symbol(strTab.getOrPut(it.name), it.entryPoint, it.length, (STB_WEAK or STT_FUNC).toByte(), 0, sectionNames.indexOf(COMBINED_0))
      }
    val externFunctionSymbols = functions
      .filter { it.import }
      .map { ExportElf.Symbol(strTab.getOrPut(it.name), 0, 0, (STB_GLOBAL or STT_NOTYPE).toByte(), 0, 0) }
    val externDataSymbols = symbols
      .filter { it.global && it.data }
      .map { ExportElf.Symbol(strTab.getOrPut(it.name), 0, 0, (STB_GLOBAL or STT_NOTYPE).toByte(), 0, 0) }

    return listOf(ExportElf.Symbol(strTab.getOrPut(""), 0, 0, 0, 0, 0)) +
      combinedSectionSymbols +
      weakFunctionSymbols +
      externFunctionSymbols +
      externDataSymbols
  }

  private fun validateElfSymbolsDuplicates(strTab: ExportElf.StringAllocator, elfSymbols: List<ExportElf.Symbol>) {
    elfSymbols.groupBy { it.name }
      .filter { it.value.size > 1 }
      .forEach { (name, _) ->
        log.appendMsg("WARN: Symbol ${strTab.lookup(name)} occurs multiple times in the symbol table")
      }
  }

  private fun createElfSections(): Pair<ExportElf.StringAllocator, List<ExportElf.Section>> {
    val shStrTab = ExportElf.StringAllocator()
    val sections = sectionNames.map { sectionName ->
      val nameOffset = shStrTab.getOrPut(sectionName)
      when (sectionName) {
        "" -> ExportElf.Section(nameOffset, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        COMBINED_0 -> ExportElf.Section(nameOffset, SHT_PROGBITS, SHF_ALLOC or SHF_EXECINSTR, 0, -1, -1, 0, 0, 4, 0)
        REL_COMBINED_0 -> {
          // link: symbol table index, info: section index for applying relocations
          ExportElf.Section(nameOffset, SHT_REL, SHF_INFO_LINK, 0, -1, -1, sectionNames.indexOf(SYMTAB), sectionNames.indexOf(COMBINED_0), 4, 8)
        }
        COMBINED_1 -> ExportElf.Section(nameOffset, SHT_PROGBITS, SHF_WRITE or SHF_ALLOC, 0, -1, -1, 0, 0, 4, 0)
        REL_COMBINED_1 -> {
          // link: symbol table index, info: section index for applying relocations
          ExportElf.Section(nameOffset, SHT_REL, SHF_INFO_LINK, 0, -1, -1, sectionNames.indexOf(SYMTAB), sectionNames.indexOf(COMBINED_1), 4, 8)
        }
        SYMTAB -> {
          // link: string table index, info: last local symbol index + 1 (in this case we only have local symbols for .combined0 and .combined1)
          ExportElf.Section(nameOffset, SHT_SYMTAB, 0, 0, -1, -1, sectionNames.indexOf(STRTAB), 0x3, 4, 0x10)
        }
        STRTAB -> ExportElf.Section(nameOffset, SHT_STRTAB, 0, 0, -1, -1, 0, 0, 1, 0)
        SHSTRTAB -> ExportElf.Section(nameOffset, SHT_STRTAB, 0, 0, -1, -1, 0, 0, 1, 0)
        else -> error("Missing setup for section $sectionName")
      }
    }
    return Pair(shStrTab, sections)
  }

  private fun createElfRelocations(
    program: Program,
    symbols: List<ModuleSymbol>,
    programBytes: List<ByteArray>,
    resolvedLoRelocations: List<ResolvedLoRelocation>,
    strTab: ExportElf.StringAllocator,
    elfSymbols: List<ExportElf.Symbol>,
  ): List<List<ExportElf.AllegrexRelocation>> {
    val elfRelocations: List<MutableList<ExportElf.AllegrexRelocation>> = listOf(mutableListOf(), mutableListOf())
    program.relocationTable.relocations.forEach { relocation ->
      val reloc = relocation.asTypeBRelocationOrThrow()
      when (relocation.type) {
        AllegrexElfRelocationConstants.R_MIPS_32 -> {
          val targetAddress = program.memory.getInt(relocation.address) - program.imageBase.offset.toInt()
          val resolvedElfSymbol = getGlobalElfSymbolForAddress(program.imageBase, symbols, elfSymbols, strTab, relocation, targetAddress)
          if (resolvedElfSymbol != null) {
            addElf32Relocation(programBytes, elfRelocations, reloc, resolvedElfSymbol.elfSymbolIndex, resolvedElfSymbol.innerOffset)
          } else {
            addElf32Relocation(programBytes, elfRelocations, reloc, reloc.addressBaseIndex + 1, null)
          }
        }
        AllegrexElfRelocationConstants.R_MIPS_LO16, AllegrexElfRelocationConstants.R_MIPS_X_HI16 -> {
          // Processed below using resolvedLoRelocations
        }
        AllegrexElfRelocationConstants.R_MIPS_X_J26 -> {
          if (reloc.offsetBase != 0L || reloc.addressBase != 0L) {
            throw ProcessingException("Not supported, jump is to or inside a non-zero section. $reloc")
          }
          elfRelocations[reloc.offsetBaseIndex].add(
            ExportElf.AllegrexRelocation(
              reloc.offset,
              AllegrexElfRelocationConstants.R_MIPS_26,
              reloc.addressBaseIndex + 1,
            )
          )
        }
        AllegrexElfRelocationConstants.R_MIPS_X_JAL26 -> {
          if (reloc.offsetBase != 0L || reloc.addressBase != 0L) {
            throw ProcessingException("Not supported, jal is to or inside a non-zero section. $reloc")
          }
          val origInstr = program.listing.getInstructionAtOrThrow(relocation.address)
          val targetAddress = origInstr.getAddress(0)
          val targetSymbol = program.symbolTable.symbolIterator.firstOrNull { it.address == targetAddress && it.isPrimary }
            ?: throw ProcessingException("Unknown symbol for JAL relocation at address ${relocation.address}, is the target function defined?")
          val elfSymbolIndex = elfSymbols.indexOfFirst { it.name == strTab.getOrPut(targetSymbol.name) }
            .takeIf { it != -1 }
            ?: throw ProcessingException("No ELF symbol for function name ${targetSymbol.name}, relocation at address ${relocation.address}")
          addElf26Relocation(programBytes, elfRelocations, reloc, elfSymbolIndex)
        }
      }
    }

    val exportedGlobalDataSymbols = mutableSetOf<String>()
    resolvedLoRelocations.forEach { resolvedLoRelocation ->
      val targetAddress = resolvedLoRelocation.targetAddress
      val resolvedElfSymbol =
        getGlobalElfSymbolForAddress(program.imageBase, symbols, elfSymbols, strTab, resolvedLoRelocation.loRelocation, targetAddress)
      resolvedLoRelocation.relatedHiRelocations.forEach { hiRelocation ->
        val hiReloc = hiRelocation.asTypeBRelocationOrThrow()
        if (resolvedElfSymbol != null) {
          addElfHiRelocation(programBytes, elfRelocations, hiReloc, resolvedElfSymbol.elfSymbolIndex, resolvedElfSymbol.innerOffset)
        } else {
          addElfHiRelocation(programBytes, elfRelocations, hiReloc, hiReloc.addressBaseIndex + 1, targetAddress)
        }
      }

      val loReloc = resolvedLoRelocation.loRelocation.asTypeBRelocationOrThrow()
      if (resolvedElfSymbol != null) {
        exportedGlobalDataSymbols.add(resolvedElfSymbol.moduleSymbol.name)
        addElfLoRelocation(programBytes, elfRelocations, loReloc, resolvedElfSymbol.elfSymbolIndex, resolvedElfSymbol.innerOffset)
      } else {
        addElfLoRelocation(programBytes, elfRelocations, loReloc, loReloc.addressBaseIndex + 1, targetAddress)
      }
    }
    log.appendMsg("\nGlobal data symbols:\n${exportedGlobalDataSymbols.joinToString("\n").ifEmpty { "(none)" }}")
    return elfRelocations
  }

  private fun addElf32Relocation(
    programBytes: List<ByteArray>,
    elfRelocations: List<MutableList<ExportElf.AllegrexRelocation>>,
    reloc: AllegrexRelocation.TypeB,
    elfSymbolIndex: Int,
    overrideExistingValue: Int?
  ) {
    if (overrideExistingValue != null) {
      programBytes[reloc.offsetBaseIndex][reloc.offset] = overrideExistingValue.toByte()
      programBytes[reloc.offsetBaseIndex][reloc.offset + 1] = (overrideExistingValue shr 8).toByte()
      programBytes[reloc.offsetBaseIndex][reloc.offset + 2] = (overrideExistingValue shr 16).toByte()
      programBytes[reloc.offsetBaseIndex][reloc.offset + 3] = (overrideExistingValue shr 24).toByte()
    }
    elfRelocations[reloc.offsetBaseIndex].add(
      ExportElf.AllegrexRelocation(
        reloc.offset,
        AllegrexElfRelocationConstants.R_MIPS_32,
        elfSymbolIndex,
      )
    )
  }

  private fun addElf26Relocation(
    programBytes: List<ByteArray>,
    elfRelocations: List<MutableList<ExportElf.AllegrexRelocation>>,
    reloc: AllegrexRelocation.TypeB,
    elfSymbolIndex: Int,
  ) {
    programBytes[reloc.offsetBaseIndex][reloc.offset] = 0
    programBytes[reloc.offsetBaseIndex][reloc.offset + 1] = 0
    programBytes[reloc.offsetBaseIndex][reloc.offset + 2] = 0
    programBytes[reloc.offsetBaseIndex][reloc.offset + 3] = 0xC
    elfRelocations[reloc.offsetBaseIndex].add(
      ExportElf.AllegrexRelocation(
        reloc.offset,
        AllegrexElfRelocationConstants.R_MIPS_26,
        elfSymbolIndex
      )
    )
  }

  private fun addElfHiRelocation(
    programBytes: List<ByteArray>,
    elfRelocations: List<MutableList<ExportElf.AllegrexRelocation>>,
    hiReloc: AllegrexRelocation.TypeB,
    elfSymbolIndex: Int,
    targetAddress: Int
  ) {
    val targetHi = targetAddress - targetAddress.toShort().toInt()
    programBytes[hiReloc.offsetBaseIndex][hiReloc.offset] = (targetHi ushr 16).toByte()
    programBytes[hiReloc.offsetBaseIndex][hiReloc.offset + 1] = (targetHi ushr 24).toByte()
    elfRelocations[hiReloc.offsetBaseIndex].add(
      ExportElf.AllegrexRelocation(
        hiReloc.offset,
        AllegrexElfRelocationConstants.R_MIPS_HI16,
        elfSymbolIndex
      )
    )
  }

  private fun addElfLoRelocation(
    programBytes: List<ByteArray>,
    elfRelocations: List<MutableList<ExportElf.AllegrexRelocation>>,
    loReloc: AllegrexRelocation.TypeB,
    elfSymbolIndex: Int,
    targetAddress: Int
  ) {
    val targetLo = targetAddress.toShort().toInt()
    programBytes[loReloc.offsetBaseIndex][loReloc.offset] = targetLo.toByte()
    programBytes[loReloc.offsetBaseIndex][loReloc.offset + 1] = (targetLo ushr 8).toByte()
    elfRelocations[loReloc.offsetBaseIndex].add(
      ExportElf.AllegrexRelocation(
        loReloc.offset,
        AllegrexElfRelocationConstants.R_MIPS_LO16,
        elfSymbolIndex,
      )
    )
  }

  private fun getGlobalElfSymbolForAddress(
    imageBase: Address,
    symbols: List<ModuleSymbol>,
    elfSymbols: List<ExportElf.Symbol>,
    strTab: ExportElf.StringAllocator,
    relocation: Relocation,
    targetAddress: Int
  ): ResolvedElfSymbol? {
    val symbolOffsetInfo = getSymbolForAddress(imageBase, symbols, relocation, targetAddress)
    val elfSymbolIndex = symbolOffsetInfo?.let { (moduleSymbol, _) ->
      elfSymbols
        .indexOfFirst { it.name == strTab.getOrPut(moduleSymbol.name) && it.info.toInt() and STB_GLOBAL != 0 }
        .takeIf { it != -1 }
    }
    if (symbolOffsetInfo == null || elfSymbolIndex == null) {
      return null
    }
    return ResolvedElfSymbol(
      moduleSymbol = symbolOffsetInfo.first,
      innerOffset = symbolOffsetInfo.second,
      elfSymbolIndex = elfSymbolIndex
    )
  }

  private fun getSymbolForAddress(
    imageBase: Address,
    symbols: List<ModuleSymbol>,
    relocation: Relocation,
    targetAddress: Int
  ): Pair<ModuleSymbol, Int>? {
    symbols.forEach { symbol ->
      if (symbol.dataLength != null) {
        if (targetAddress >= symbol.address && targetAddress < symbol.address + symbol.dataLength) {
          return symbol to (targetAddress - symbol.address)
        }
      } else {
        if (targetAddress == symbol.address) {
          return symbol to 0
        }
      }
    }
    log.appendMsg(
      "WARN: No symbol for address ${imageBase.add(targetAddress.toLong() and 0xFFFFFFFF)}. " +
        "Relocation type ${relocation.type}, relocation at address ${relocation.address}"
    )
    return null
  }

  private data class ResolvedLoRelocation(
    val loRelocation: Relocation,
    val relatedHiRelocations: List<Relocation>,
    val targetAddress: Int,
  )

  private data class ResolvedElfSymbol(
    val moduleSymbol: ModuleSymbol,
    val innerOffset: Int,
    val elfSymbolIndex: Int,
  )

  private data class ModuleSymbol(
    val name: String,
    val address: Int,
    val dataLength: Int?,
    val global: Boolean,
    val data: Boolean,
  )

  private data class ModuleFunction(
    val name: String,
    val entryPoint: Int,
    val length: Int,
    val import: Boolean,
  )

  private fun Relocation.asTypeBRelocationOrThrow(): AllegrexRelocation.TypeB {
    val reloc = AllegrexRelocation.fromLongArray(values)
    if (reloc !is AllegrexRelocation.TypeB) {
      throw ProcessingException("Type A relocation in kernel module is not supported. Relocation type $type, relocation at address $address")
    }
    return reloc
  }

  private fun Listing.getInstructionAtOrThrow(address: Address): Instruction {
    return getInstructionAt(address)
      ?: throw ProcessingException("There is no instruction defined at $address, is code disassembled there?")
  }

  private class ProcessingException(message: String) : Exception(message)
}
