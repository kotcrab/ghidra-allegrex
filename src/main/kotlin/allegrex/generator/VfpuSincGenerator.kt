package allegrex.generator

import java.io.File

private const val INSTRUCTION_PADDING = 34
private const val GENERATE_IMPLEMENTATION = true

fun main(args: Array<String>) {
  val outputFile = when {
    args.isNotEmpty() -> File(args[0])
    else -> null
  }
  VfpuSincGenerator(outputFile)
}

class VfpuSincGenerator(outputFile: File?) {
  private val builder = StringBuilder()

  init {
    generateHeader()
    generateVpfxdTables()
    generateVpfxstTables()
    generateVrotTables()
    generateCcTables()
    generateCmovCcTables()
    generateInstructions()
    when {
      outputFile != null -> outputFile.writeText(builder.toString())
      else -> println(builder.toString())
    }
  }

  private fun generateHeader() {
    builder.append("# DO NOT MODIFY. THIS FILE IS AUTO-GENERATED.\n\n")
  }

  private fun generateVpfxdTables() {
    fun template(opId: Int) = """
VpfxdOp$opId: ""      is vpfxd_op$opId = 0   { export 1:1; }
VpfxdOp$opId: "0:1"   is vpfxd_op$opId = 1   { export 2:1; }
VpfxdOp$opId: "X"     is vpfxd_op$opId = 2   { export 3:1; }
VpfxdOp$opId: "-1:1"  is vpfxd_op$opId = 3   { export 4:1; }
VpfxdMask$opId: ""    is vpfxd_mask$opId = 0 { export 0:1; }
VpfxdMask$opId: "M"   is vpfxd_mask$opId = 1 { export 1:1; }
Vpfxd$opId: VpfxdOp$opId^VpfxdMask$opId is VpfxdOp$opId & VpfxdMask$opId {
    local tmpOp:1 = (VpfxdMask$opId << 2) | VpfxdOp$opId;
    export tmpOp;
}
    """.trimIndent()

    repeat(4) {
      builder.append(template(it))
      builder.append("\n\n")
    }
  }

  private fun generateVpfxstTables() {
    fun template(opId: Int) = """
VpfxstNeg$opId: ""      is vpfxst_neg$opId = 0                   { export 0:1; }
VpfxstNeg$opId: "-"     is vpfxst_neg$opId = 1                   { export 1:1; }
VpfxstPreAbs$opId: ""   is (vpfxst_abs$opId = 0 & vpfxst_cst$opId = 0) | (vpfxst_abs$opId = 0 & vpfxst_cst$opId = 1) | (vpfxst_abs$opId = 1 & vpfxst_cst$opId = 1) { export 0:1; }
VpfxstPreAbs$opId: "|"  is vpfxst_abs$opId = 1 & vpfxst_cst$opId = 0 { export 1:1; }
VpfxstPostAbs$opId: ""  is (vpfxst_abs$opId = 0 & vpfxst_cst$opId = 0) | (vpfxst_abs$opId = 0 & vpfxst_cst$opId = 1) | (vpfxst_abs$opId = 1 & vpfxst_cst$opId = 1) { export 0:1; }
VpfxstPostAbs$opId: "|" is vpfxst_abs$opId = 1 & vpfxst_cst$opId = 0 { export 1:1; }
VpfxstOp$opId: "X"      is vpfxst_op$opId  = 0 & vpfxst_cst$opId = 0 { export 0:1; }
VpfxstOp$opId: "Y"      is vpfxst_op$opId  = 1 & vpfxst_cst$opId = 0 { export 1:1; }
VpfxstOp$opId: "Z"      is vpfxst_op$opId  = 2 & vpfxst_cst$opId = 0 { export 2:1; }
VpfxstOp$opId: "W"      is vpfxst_op$opId  = 3 & vpfxst_cst$opId = 0 { export 3:1; }
VpfxstOp$opId: "0"      is vpfxst_op$opId  = 0 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 0 { export 0:1; }
VpfxstOp$opId: "1"      is vpfxst_op$opId  = 1 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 0 { export 1:1; }
VpfxstOp$opId: "2"      is vpfxst_op$opId  = 2 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 0 { export 2:1; }
VpfxstOp$opId: "1/2"    is vpfxst_op$opId  = 3 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 0 { export 3:1; }
VpfxstOp$opId: "3"      is vpfxst_op$opId  = 0 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 1 { export 4:1; }
VpfxstOp$opId: "1/3"    is vpfxst_op$opId  = 1 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 1 { export 5:1; }
VpfxstOp$opId: "1/4"    is vpfxst_op$opId  = 2 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 1 { export 6:1; }
VpfxstOp$opId: "1/6"    is vpfxst_op$opId  = 3 & vpfxst_cst$opId = 1 & vpfxst_abs$opId = 1 { export 7:1; }
Vpfxst$opId: VpfxstNeg$opId^VpfxstPreAbs$opId^VpfxstOp$opId^VpfxstPostAbs$opId is VpfxstNeg$opId & VpfxstPreAbs$opId & VpfxstOp$opId & VpfxstPostAbs$opId & vpfxst_cst$opId {
    local tmpOp:1 = (VpfxstNeg$opId << 4) | (VpfxstPreAbs$opId << 3) | (vpfxst_cst$opId << 2) |  VpfxstOp$opId;
    export tmpOp;
}
    """.trimIndent()

    repeat(4) {
      builder.append(template(it))
      builder.append("\n\n")
    }
  }

  private fun generateVrotTables() {
    fun template(idx: Int) = """
VfpuRot$idx: "C"  is vrot_imm0 = $idx                                          { export 1:1; }
VfpuRot$idx: "-S" is vrot_neg = 1 & (vrot_imm1 = $idx | vrot_imm0 = vrot_imm1) { export 3:1; }
VfpuRot$idx: "S"  is vrot_imm1 = $idx                                          { export 2:1; }
VfpuRot$idx: "S"  is vrot_imm0 = vrot_imm1                                     { export 2:1; }
VfpuRot$idx: "0"  is epsilon                                                   { export 0:1; } # epsilon matches all
    """.trimIndent()

    repeat(4) {
      builder.append(template(it))
      builder.append("\n\n")
    }
  }

  private fun generateCcTables() {
    fun template(idx: Int) = """VfpuCC: "CC[$idx]" is vcc = $idx { local tmpCc:1 = CC[$idx,1]; export tmpCc; }"""
    repeat(8) {
      builder.append(template(it))
      builder.append("\n")
    }
    builder.append("\n")
  }

  private fun generateCmovCcTables() {
    fun template(idx: Int) = """VfpuCmovCC: "CC[$idx]" is vcmov_cc = $idx { local tmpCc:1 = CC[$idx,1]; export tmpCc; }"""
    repeat(8) {
      builder.append(template(it))
      builder.append("\n")
    }
    builder.append("\n")
  }

  private fun generateInstructions() {
    add3("vadd", prime = 24, vop3 = 0) { variantsAllToAll() }
    add3("vsub", prime = 24, vop3 = 1) { variantsAllToAll() }
    add3("vsbn", prime = 24, vop3 = 2) { variantsAllToAll() }
    add3("vdiv", prime = 24, vop3 = 7) { variantsAllToAll() }
    add3("vmul", prime = 25, vop3 = 0) { variantsAllToAll() }
    add3("vdot", prime = 25, vop3 = 1) { variantsAllToS() }
    add3("vscl", prime = 25, vop3 = 2) {
      variantS(Vd.S, Vs.S, Vt.S)
      variantP(Vd.P, Vs.P, Vt.S)
      variantT(Vd.T, Vs.T, Vt.S)
      variantQ(Vd.Q, Vs.Q, Vt.S)
    }
    add3("vhdp", prime = 25, vop3 = 4) { variantsAllToS() }
    add3("vcrs", prime = 25, vop3 = 5) { variantT(Vd.T, Vs.T, Vt.T) }
    add3("vdet", prime = 25, vop3 = 6) { variantsAllToS() }
    add3("vmin", prime = 27, vop3 = 2) { variantsAllToAll() }
    add3("vmax", prime = 27, vop3 = 3) { variantsAllToAll() }
    add3("vscmp", prime = 27, vop3 = 5) { variantsAllToAll() }
    add3("vsge", prime = 27, vop3 = 6) { variantsAllToAll() }
    add3("vslt", prime = 27, vop3 = 7) { variantsAllToAll() }
    add3("vcrsp", prime = 60, vop3 = 5) { variantT(Vd.T, Vs.T, Vt.T) }
    add3("vqmul", prime = 60, vop3 = 5) { variantQ(Vd.Q, Vs.Q, Vt.Q) }
    add2("vmov", vt = 0) { variantsAllToAll() }
    add2("vabs", vt = 1) { variantsAllToAll() }
    add2("vneg", vt = 2) { variantsAllToAll() }
    add1("vidt", vt = 3) { variantsAllToAll() }
    add2("vsat0", vt = 4) { variantsAllToAll() }
    add2("vsat1", vt = 5) { variantsAllToAll() }
    add1("vzero", vt = 6) { variantsAllToAll() }
    add1("vone", vt = 7) { variantsAllToAll() }
    add2("vrcp", vt = 16) { variantsAllToAll() }
    add2("vrsq", vt = 17) { variantsAllToAll() }
    add2("vsin", vt = 18) { variantsAllToAll() }
    add2("vcos", vt = 19) { variantsAllToAll() }
    add2("vexp2", vt = 20) { variantsAllToAll() }
    add2("vlog2", vt = 21) { variantsAllToAll() }
    add2("vsqrt", vt = 22) { variantsAllToAll() }
    add2("vasin", vt = 23) { variantsAllToAll() }
    add2("vnrcp", vt = 24) { variantsAllToAll() }
    add2("vnsin", vt = 26) { variantsAllToAll() }
    add2("vrexp2", vt = 28) { variantsAllToAll() }
    add1("vrnds", vt = 32) { variantsAllToS() }
    add1("vrndi", vt = 33) { variantsAllToAll() }
    add1("vrndf1", vt = 34) { variantsAllToAll() }
    add1("vrndf2", vt = 35) { variantsAllToAll() }
    add2("vsbz", vt = 44) { variant(Variant.None, Vd.S, Vs.S) }
    add2("vf2h", vt = 50) {
      variantP(Vd.S, Vs.P)
      variantQ(Vd.P, Vs.Q)
    }
    add2("vh2f", vt = 51) {
      variantS(Vd.P, Vs.S)
      variantP(Vd.P, Vs.P)
    }
    add2("vlgb", vt = 55) { variant(Variant.None, Vd.S, Vs.S) }
    add2("vuc2i", vt = 56) { variantsAllToAll() }
    add2("vc2i", vt = 57) { variantsAllToAll() }
    add2("vus2i", vt = 58) { variantsAllToAll() }
    add2("vs2i", vt = 59) { variantsAllToAll() }
    add2("vi2uc", vt = 60) { variantsAllToS() }
    add2("vi2c", vt = 61) { variantsPSPAndQQQ() }
    add2("vi2us", vt = 62) { variantsPSPAndQQQ() }
    add2("vi2s", vt = 63) { variantsPSPAndQQQ() }
    add2("vsrt1", vt = 64) { variantsAllToAll() }
    add2("vsrt2", vt = 65) { variantsAllToAll() }
    add2("vbfy1", vt = 66) { variantsAllToAll() }
    add2("vbfy2", vt = 67) { variantsAllToAll() }
    add2("vocp", vt = 68) { variantsAllToAll() }
    add2("vsocp", vt = 69) { variantsAllToAll() }
    add2("vfad", vt = 70) { variantsAllToS() }
    add2("vavg", vt = 71) { variantsAllToS() }
    add2("vsrt3", vt = 72) { variantsAllToAll() }
    add2("vsrt4", vt = 73) { variantsAllToAll() }
    add2("vsgn", vt = 74) { variantsAllToAll() }
    add2("vt4444", vt = 89) { variantsPSPAndQQQ() }
    add2("vt5551", vt = 90) { variantsPSPAndQQQ() }
    add2("vt5650", vt = 91) { variantsPSPAndQQQ() }

    add3Imm("vf2in", vop3 = 4, extraCondition = "vtop2 = 0", immName = "vtimm5") { variantsAllToAll() }
    add3Imm("vf2iz", vop3 = 4, extraCondition = "vtop2 = 1", immName = "vtimm5") { variantsAllToAll() }
    add3Imm("vf2iu", vop3 = 4, extraCondition = "vtop2 = 2", immName = "vtimm5") { variantsAllToAll() }
    add3Imm("vf2id", vop3 = 4, extraCondition = "vtop2 = 3", immName = "vtimm5") { variantsAllToAll() }
    add3Imm("vi2f", vop3 = 5, extraCondition = "vtop2 = 0", immName = "vtimm5") { variantsAllToAll() }
    add3Imm("vcmovt", vop3 = 5, extraCondition = "vcmov_op = 4", immName = "VfpuCmovCC", immSize = 1) { variantsAllToAll() }
    add3Imm("vcmovf", vop3 = 5, extraCondition = "vcmov_op = 5", immName = "VfpuCmovCC", immSize = 1) { variantsAllToAll() }
    add3Imm("vwbn", vop3 = null, extraCondition = "vop2 = 3", immName = "vwbnimm8") { variantsAllToAll() }

    add3("vmmul", prime = 60, vop3 = 0) {
      variantS(Vd.Matrix1, Vs.Matrix1Transposed, Vt.Matrix1)
      variantP(Vd.Matrix2, Vs.Matrix2Transposed, Vt.Matrix2)
      variantT(Vd.Matrix3, Vs.Matrix3Transposed, Vt.Matrix3)
      variantQ(Vd.Matrix4, Vs.Matrix4Transposed, Vt.Matrix4)
    }
    add3("vhtfm1", prime = 60, vop3 = 1) { variantS(Vd.S, Vs.Matrix1, Vt.S) }
    add3("vtfm2", prime = 60, vop3 = 1) { variantP(Vd.P, Vs.Matrix2, Vt.P) }
    add3("vhtfm2", prime = 60, vop3 = 2) { variantP(Vd.P, Vs.Matrix2, Vt.P) }
    add3("vtfm3", prime = 60, vop3 = 2) { variantT(Vd.T, Vs.Matrix3, Vt.T) }
    add3("vhtfm3", prime = 60, vop3 = 3) { variantT(Vd.T, Vs.Matrix3, Vt.T) }
    add3("vtfm4", prime = 60, vop3 = 3) { variantQ(Vd.Q, Vs.Matrix2, Vt.Q) }
    add3("vmscl", prime = 60, vop3 = 4) {
      variantS(Vd.Matrix1, Vs.Matrix1, Vt.S)
      variantP(Vd.Matrix2, Vs.Matrix2, Vt.S)
      variantT(Vd.Matrix3, Vs.Matrix3, Vt.S)
      variantQ(Vd.Matrix4, Vs.Matrix4, Vt.S)
    }
    add2("vmmov", prime = 60, vop3 = 7, vt = null, extraCondition = "vtop2 = 0 & vtop4 = 0") {
      variantS(Vd.Matrix1, Vs.Matrix1)
      variantP(Vd.Matrix2, Vs.Matrix2)
      variantT(Vd.Matrix3, Vs.Matrix3)
      variantQ(Vd.Matrix4, Vs.Matrix4)
    }
    add1("vmidt", prime = 60, vop3 = 7, vt = null, extraCondition = "vtop2 = 0 & vtop4 = 3") { variantsMatrixAllToAll() }
    add1("vmzero", prime = 60, vop3 = 7, vt = null, extraCondition = "vtop2 = 0 & vtop4 = 6") { variantsMatrixAllToAll() }
    add1("vmone", prime = 60, vop3 = 7, vt = null, extraCondition = "vtop2 = 0 & vtop4 = 7") { variantsMatrixAllToAll() }
  }

  private fun add1(
    name: String,
    prime: Int = 52,
    vop3: Int = 0,
    vt: Int?,
    extraCondition: String? = null,
    block: InstructionGeneratorOp1.() -> Unit
  ) {
    add(InstructionGeneratorOp1(name = name, prime = prime, vop3 = vop3, vt = vt, extraCondition = extraCondition).apply { block() })
  }

  private fun add2(
    name: String,
    prime: Int = 52,
    vop3: Int = 0,
    vt: Int?,
    extraCondition: String? = null,
    block: InstructionGeneratorOp2.() -> Unit
  ) {
    add(InstructionGeneratorOp2(name = name, prime = prime, vop3 = vop3, vt = vt, extraCondition = extraCondition).apply { block() })
  }

  private fun add3(
    name: String,
    prime: Int,
    vop3: Int,
    block: InstructionGeneratorOp3.() -> Unit
  ) {
    add(InstructionGeneratorOp3(name = name, prime = prime, vop3 = vop3).apply { block() })
  }

  private fun add3Imm(
    name: String,
    prime: Int = 52,
    vop3: Int?,
    immName: String,
    immSize: Int = 4,
    extraCondition: String,
    block: InstructionGeneratorOp3Imm.() -> Unit
  ) {
    add(InstructionGeneratorOp3Imm(name, prime, vop3, immName, immSize, extraCondition).apply { block() })
  }

  private fun add(generator: InstructionGenerator) {
    builder.append(generator.generate())
    builder.append("\n")
  }
}

private class InstructionGeneratorOp1(
  private val name: String,
  private val prime: Int,
  private val vop3: Int,
  private val vt: Int?,
  private val extraCondition: String?
) : InstructionGenerator {
  private val builder = StringBuilder()

  fun variantsAllToAll() {
    variantS(Vd.S)
    variantP(Vd.P)
    variantT(Vd.T)
    variantQ(Vd.Q)
  }

  fun variantsAllToS() {
    variantS(Vd.S)
    variantP(Vd.S)
    variantT(Vd.S)
    variantQ(Vd.S)
  }

  fun variantsMatrixAllToAll() {
    variantS(Vd.Matrix1)
    variantP(Vd.Matrix2)
    variantT(Vd.Matrix3)
    variantQ(Vd.Matrix4)
  }

  fun variantS(vd: Vd) = variant(Variant.S, vd)
  fun variantP(vd: Vd) = variant(Variant.P, vd)
  fun variantT(vd: Vd) = variant(Variant.T, vd)
  fun variantQ(vd: Vd) = variant(Variant.Q, vd)

  fun variant(variant: Variant, vd: Vd) {
    val pcodeName = "${name}${variant.suffix.replace(".", "_")}"
    if (GENERATE_IMPLEMENTATION) {
      builder.append("define pcodeop $pcodeName;\n")
    }
    builder.append(":$name${variant.suffix} ${vd.asmName}".padEnd(INSTRUCTION_PADDING))
    builder.append("is prime = $prime & vop3 = $vop3 & ")
    if (vt != null) {
      builder.append("vt = $vt & ")
    }
    if (extraCondition != null) {
      builder.append("$extraCondition & ")
    }
    if (variant.matcher.isNotEmpty()) {
      builder.append("${variant.matcher} & ")
    }
    builder.append(vd.matcher)
    if (GENERATE_IMPLEMENTATION) {
      builder.append(
        """   {
        |    local result:${vd.sleighSize} = $pcodeName();
        |    ${vd.sleighWriter("result")}
        |}
      """.trimMargin()
      )
      builder.append("\n\n")
    } else {
      builder.append("   unimpl\n")
    }
  }

  override fun generate(): String {
    return builder.toString()
  }
}

private class InstructionGeneratorOp2(
  private val name: String,
  private val prime: Int,
  private val vop3: Int,
  private val vt: Int?,
  private val extraCondition: String?
) : InstructionGenerator {
  private val builder = StringBuilder()

  fun variantsAllToAll() {
    variantS(Vd.S, Vs.S)
    variantP(Vd.P, Vs.P)
    variantT(Vd.T, Vs.T)
    variantQ(Vd.Q, Vs.Q)
  }

  fun variantsAllToS() {
    variantS(Vd.S, Vs.S)
    variantP(Vd.S, Vs.P)
    variantT(Vd.S, Vs.T)
    variantQ(Vd.S, Vs.Q)
  }

  fun variantsPSPAndQQQ() {
    variantP(Vd.S, Vs.P)
    variantQ(Vd.Q, Vs.Q)
  }

  fun variantS(vd: Vd, vs: Vs) = variant(Variant.S, vd, vs)
  fun variantP(vd: Vd, vs: Vs) = variant(Variant.P, vd, vs)
  fun variantT(vd: Vd, vs: Vs) = variant(Variant.T, vd, vs)
  fun variantQ(vd: Vd, vs: Vs) = variant(Variant.Q, vd, vs)

  fun variant(variant: Variant, vd: Vd, vs: Vs) {
    val pcodeName = "${name}${variant.suffix.replace(".", "_")}"
    if (GENERATE_IMPLEMENTATION) {
      builder.append("define pcodeop $pcodeName;\n")
    }
    builder.append(":$name${variant.suffix} ${vd.asmName}, ${vs.asmName}".padEnd(INSTRUCTION_PADDING))
    builder.append("is prime = $prime & vop3 = $vop3 & ")
    if (vt != null) {
      builder.append("vt = $vt & ")
    }
    if (extraCondition != null) {
      builder.append("$extraCondition & ")
    }
    if (variant.matcher.isNotEmpty()) {
      builder.append("${variant.matcher} & ")
    }
    builder.append("${vd.matcher} & ${vs.matcher}")
    if (GENERATE_IMPLEMENTATION) {
      builder.append(
        """   {
        |    local op1:${vs.sleighSize} = ${vs.sleighReader};
        |    local result:${vd.sleighSize} = $pcodeName(op1);
        |    ${vd.sleighWriter("result")}
        |}
        |
      """.trimMargin()
      )
    } else {
      builder.append("   unimpl\n")
    }
  }

  override fun generate(): String {
    return builder.toString()
  }
}

private class InstructionGeneratorOp3(
  private val name: String,
  private val prime: Int,
  private val vop3: Int
) : InstructionGenerator {
  private val builder = StringBuilder()

  fun variantsAllToAll() {
    variantS(Vd.S, Vs.S, Vt.S)
    variantP(Vd.P, Vs.P, Vt.P)
    variantT(Vd.T, Vs.T, Vt.T)
    variantQ(Vd.Q, Vs.Q, Vt.Q)
  }

  fun variantsAllToS() {
    variantS(Vd.S, Vs.S, Vt.S)
    variantP(Vd.S, Vs.P, Vt.P)
    variantT(Vd.S, Vs.T, Vt.T)
    variantQ(Vd.S, Vs.Q, Vt.Q)
  }

  fun variantS(vd: Vd, vs: Vs, vt: Vt) = variant(Variant.S, vd, vs, vt)
  fun variantP(vd: Vd, vs: Vs, vt: Vt) = variant(Variant.P, vd, vs, vt)
  fun variantT(vd: Vd, vs: Vs, vt: Vt) = variant(Variant.T, vd, vs, vt)
  fun variantQ(vd: Vd, vs: Vs, vt: Vt) = variant(Variant.Q, vd, vs, vt)

  fun variant(variant: Variant, vd: Vd, vs: Vs, vt: Vt) {
    val pcodeName = "${name}${variant.suffix.replace(".", "_")}"
    if (GENERATE_IMPLEMENTATION) {
      builder.append("define pcodeop $pcodeName;\n")
    }
    builder.append(":$name${variant.suffix} ${vd.asmName}, ${vs.asmName}, ${vt.asmName}".padEnd(INSTRUCTION_PADDING))
    builder.append("is prime = $prime & vop3 = $vop3 & ")
    if (variant.matcher.isNotEmpty()) {
      builder.append("${variant.matcher} & ")
    }
    builder.append("${vd.matcher} & ${vs.matcher} & ${vt.matcher}")
    if (GENERATE_IMPLEMENTATION) {
      builder.append(
        """   {
        |    local op1:${vs.sleighSize} = ${vs.sleighReader};
        |    local op2:${vt.sleighSize} = ${vt.sleighReader};
        |    local result:${vd.sleighSize} = $pcodeName(op1, op2);
        |    ${vd.sleighWriter("result")}
        |}
        |
      """.trimMargin()
      )
    } else {
      builder.append("   unimpl\n")
    }
  }

  override fun generate(): String {
    return builder.toString()
  }
}

private class InstructionGeneratorOp3Imm(
  private val name: String,
  private val prime: Int,
  private val vop3: Int?,
  private val immName: String,
  private val immSize: Int,
  private val extraCondition: String
) : InstructionGenerator {
  private val builder = StringBuilder()

  fun variantsAllToAll() {
    variantS(Vd.S, Vs.S)
    variantP(Vd.P, Vs.P)
    variantT(Vd.T, Vs.T)
    variantQ(Vd.Q, Vs.Q)
  }

  fun variantS(vd: Vd, vs: Vs) = variant(Variant.S, vd, vs)
  fun variantP(vd: Vd, vs: Vs) = variant(Variant.P, vd, vs)
  fun variantT(vd: Vd, vs: Vs) = variant(Variant.T, vd, vs)
  fun variantQ(vd: Vd, vs: Vs) = variant(Variant.Q, vd, vs)

  fun variant(variant: Variant, vd: Vd, vs: Vs) {
    val pcodeName = "${name}${variant.suffix.replace(".", "_")}"
    if (GENERATE_IMPLEMENTATION) {
      builder.append("define pcodeop $pcodeName;\n")
    }
    builder.append(":$name${variant.suffix} ${vd.asmName}, ${vs.asmName}, $immName".padEnd(INSTRUCTION_PADDING))
    builder.append("is prime = $prime & ")
    if (vop3 != null) {
      builder.append("vop3 = $vop3 & ")
    }
    builder.append("$extraCondition & ")
    if (variant.matcher.isNotEmpty()) {
      builder.append("${variant.matcher} & ")
    }
    builder.append("${vd.matcher} & ${vs.matcher} & $immName")
    if (GENERATE_IMPLEMENTATION) {
      builder.append(
        """   {
        |    local op1:${vs.sleighSize} = ${vs.sleighReader};
        |    local result:${vd.sleighSize} = $pcodeName(op1, $immName:$immSize);
        |    ${vd.sleighWriter("result")}
        |}
        |
      """.trimMargin()
      )
    } else {
      builder.append("   unimpl\n")
    }
  }

  override fun generate(): String {
    return builder.toString()
  }
}

private interface InstructionGenerator {
  fun generate(): String
}

private enum class Variant(val suffix: String, val matcher: String) {
  None("", ""),
  S(".s", "vc1 = 0 & vc0 = 0"),
  P(".p", "vc1 = 0 & vc0 = 1"),
  T(".t", "vc1 = 1 & vc0 = 0"),
  Q(".q", "vc1 = 1 & vc0 = 1"),
}

private enum class Vd(
  val asmName: String,
  val matcher: String,
  val sleighSize: String,
  val sleighWriter: (String) -> String
) {
  S(
    asmName = "vd_s",
    matcher = "vd_s & vd",
    sleighSize = "4",
    sleighWriter = { "vd = $it;" }
  ),
  P(
    asmName = "vd_p",
    matcher = "vd_p & vd",
    sleighSize = "8",
    sleighWriter = { "vfpuWriteP(vd, $it[0,32], $it[32,32]);" }),
  T(
    asmName = "vd_t",
    matcher = "vd_t & vd",
    sleighSize = "12",
    sleighWriter = { "vfpuWriteT(vd, $it[0,32], $it[32,32], $it[64,32]);" }),
  Q(
    asmName = "vd_q",
    matcher = "vd_q & vd",
    sleighSize = "16",
    sleighWriter = { "vfpuWriteQ(vd, $it[0,32], $it[32,32], $it[64,32], $it[96,32]);" }),
  Matrix1(
    asmName = "vd_m",
    matcher = "vd_m & vd",
    sleighSize = "4",
    sleighWriter = { "vd = $it;" }
  ),
  Matrix2(
    asmName = "vd_m",
    matcher = "vd_m & vd",
    sleighSize = "16",
    sleighWriter = {
      """
    |vfpuWriteMatrix2(vd, 0:1, $it[0,32], $it[32,32]);
    |    vfpuWriteMatrix2(vd, 1:1, $it[64,32], $it[96,32]);
    """.trimMargin()
    }
  ),
  Matrix3(
    asmName = "vd_tm",
    matcher = "vd_tm & vd",
    sleighSize = "36",
    sleighWriter = {
      """
    |vfpuWriteMatrix3(vd, 0:1, $it[0,32], $it[32,32], $it[64,32]);
    |    vfpuWriteMatrix3(vd, 1:1, $it[96,32], $it[128,32], $it[160,32]);
    |    vfpuWriteMatrix3(vd, 2:1, $it[192,32], $it[224,32], $it[256,32]);
    """.trimMargin()
    }
  ),
  Matrix4(
    asmName = "vd_m",
    matcher = "vd_m & vd",
    sleighSize = "64",
    sleighWriter = {
      """
    |vfpuWriteMatrix4(vd, 0:1, $it[0,32], $it[32,32], $it[64,32], $it[96,32]);
    |    vfpuWriteMatrix4(vd, 1:1, $it[128,32], $it[160,32], $it[192,32], $it[224,32]);
    |    vfpuWriteMatrix4(vd, 2:1, $it[256,32], $it[288,32], $it[320,32], $it[352,32]);
    |    vfpuWriteMatrix4(vd, 3:1, $it[384,32], $it[416,32], $it[448,32], $it[480,32]);
    """.trimMargin()
    }
  ),
}

private enum class Vs(val asmName: String, val matcher: String, val sleighSize: String, val sleighReader: String) {
  S(
    asmName = "vs_s",
    matcher = "vs_s & vs",
    sleighSize = "4",
    sleighReader = "vs"
  ),
  P(
    asmName = "vs_p",
    matcher = "vs_p & vs",
    sleighSize = "8",
    sleighReader = "vfpuReadP(vs)"
  ),
  T(
    asmName = "vs_t",
    matcher = "vs_t & vs",
    sleighSize = "12",
    sleighReader = "vfpuReadT(vs)"
  ),
  Q(
    asmName = "vs_q",
    matcher = "vs_q & vs",
    sleighSize = "16",
    sleighReader = "vfpuReadQ(vs)"
  ),
  Matrix1(
    asmName = "vs_m",
    matcher = "vs_m & vs",
    sleighSize = "4",
    sleighReader = "vs"
  ),
  Matrix1Transposed(
    asmName = "vs_e",
    matcher = "vs_e & vs",
    sleighSize = "4",
    sleighReader = "vs"
  ),
  Matrix2(
    asmName = "vs_m",
    matcher = "vs_m & vs",
    sleighSize = "16",
    sleighReader = "vfpuReadMatrix2(vs, 0:1)"
  ),
  Matrix2Transposed(
    asmName = "vs_e",
    matcher = "vs_e & vs",
    sleighSize = "16",
    sleighReader = "vfpuReadMatrix2(vs, 1:1)"
  ),
  Matrix3(
    asmName = "vs_tm",
    matcher = "vs_tm & vs",
    sleighSize = "36",
    sleighReader = "vfpuReadMatrix3(vs, 0:1)"
  ),
  Matrix3Transposed(
    asmName = "vs_te",
    matcher = "vs_te & vs",
    sleighSize = "36",
    sleighReader = "vfpuReadMatrix3(vs, 1:1)"
  ),
  Matrix4(
    asmName = "vs_m",
    matcher = "vs_m & vs",
    sleighSize = "64",
    sleighReader = "vfpuReadMatrix4(vs, 0:1)"
  ),
  Matrix4Transposed(
    asmName = "vs_e",
    matcher = "vs_e & vs",
    sleighSize = "64",
    sleighReader = "vfpuReadMatrix4(vs, 1:1)"
  ),
}

private enum class Vt(val asmName: String, val matcher: String, val sleighSize: String, val sleighReader: String) {
  S(
    asmName = "vt_s",
    matcher = "vt_s & vt",
    sleighSize = "4",
    sleighReader = "vt"
  ),
  P(
    asmName = "vt_p",
    matcher = "vt_p & vt",
    sleighSize = "8",
    sleighReader = "vfpuReadP(vt)"
  ),
  T(
    asmName = "vt_t",
    matcher = "vt_t & vt",
    sleighSize = "12",
    sleighReader = "vfpuReadT(vt)"
  ),
  Q(
    asmName = "vt_q",
    matcher = "vt_q & vt",
    sleighSize = "16",
    sleighReader = "vfpuReadQ(vt)"
  ),
  Matrix1(
    asmName = "vt_m",
    matcher = "vt_m & vt",
    sleighSize = "4",
    sleighReader = "vt"
  ),
  Matrix2(
    asmName = "vt_m",
    matcher = "vt_m & vt",
    sleighSize = "16",
    sleighReader = "vfpuReadMatrix2(vt, 0:1)"
  ),
  Matrix2Transposed(
    asmName = "vt_m",
    matcher = "vt_m & vt",
    sleighSize = "16",
    sleighReader = "vfpuReadMatrix2(vt, 1:1)"
  ),
  Matrix3(
    asmName = "vt_tm",
    matcher = "vt_tm & vt",
    sleighSize = "36",
    sleighReader = "vfpuReadMatrix3(vt, 0:1)"
  ),
  Matrix3Transposed(
    asmName = "vt_tm",
    matcher = "vt_tm & vt",
    sleighSize = "36",
    sleighReader = "vfpuReadMatrix3(vt, 1:1)"
  ),
  Matrix4(
    asmName = "vt_m",
    matcher = "vt_m & vt",
    sleighSize = "64",
    sleighReader = "vfpuReadMatrix4(vt, 0:1)"
  ),
  Matrix4Transposed(
    asmName = "vt_m",
    matcher = "vt_m & vt",
    sleighSize = "64",
    sleighReader = "vfpuReadMatrix4(vt, 1:1)"
  ),
}
