package ghidra.app.util.opinion

import allegrex.format.elf.PspElfHeader
import ghidra.app.util.Option
import ghidra.app.util.OptionUtils
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.bin.format.elf.ElfException
import ghidra.app.util.importer.MessageLog
import ghidra.framework.model.DomainObject
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import java.io.IOException

class PspElfLoader : ElfLoader() {
  companion object {
    const val PSP_ELF_NAME = "PSP Executable (ELF)"

    object Options {
      private const val COMMAND_LINE_ARG_PREFIX = "-psp"

      object UseRebootBinTypeBMapping {
        private const val NAME = "Use reboot.bin Type B Relocation Mapping"
        private const val DEFAULT = false
        private val TYPE = java.lang.Boolean::class.java // must be Java Boolean
        private const val COMMAND_LINE = "${COMMAND_LINE_ARG_PREFIX}-useRebootBinTypeBRelocationMapping"

        fun toOption(): Option {
          return Option(NAME, DEFAULT, TYPE, COMMAND_LINE)
        }

        fun getValue(options: List<Option>): Boolean {
          return OptionUtils.getOption(NAME, options, DEFAULT)
        }
      }
    }
  }

  override fun getName(): String {
    return PSP_ELF_NAME
  }

  override fun getTier(): LoaderTier {
    return LoaderTier.SPECIALIZED_TARGET_LOADER
  }

  override fun getTierPriority(): Int {
    return 0
  }

  override fun getDefaultOptions(
    provider: ByteProvider?,
    loadSpec: LoadSpec?,
    domainObject: DomainObject?,
    loadIntoProgram: Boolean,
    mirrorFsLayout: Boolean,
  ): MutableList<Option> {
    val options = super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout)
    options.add(Options.UseRebootBinTypeBMapping.toOption())
    return options
  }

  override fun load(program: Program, settings: Loader.ImporterSettings) {
    try {
      val elf = PspElfHeader(settings.provider, Options.UseRebootBinTypeBMapping.getValue(settings.options)) {
        settings.log.appendMsg(it)
      }
      ElfProgramBuilder.loadElf(elf, program, settings.options, settings.log, settings.monitor)
      program.executableFormat = PSP_ELF_NAME
    } catch (e: ElfException) {
      throw IOException(e.message)
    }
  }
}
