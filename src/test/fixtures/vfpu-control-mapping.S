/* Source-owned PSP VFPU control-operand mapping regression.
 * Preserve the original vpfx* calls and test only scalar/control transfers.
 * a0 points to at least 12 writable bytes.
 */
    .text
    .set noreorder
    .word 0x340800e4  /* ori t0,zero,0xe4 */
    .word 0x48e80000  /* mtv t0,S000 */
    .word 0xd0510001  /* vmtvc S000,TPFX */
    .word 0x34080001  /* ori t0,zero,1 */
    .word 0x48e80000  /* mtv t0,S000 */
    .word 0xd0500100  /* vmfvc S000,TPFX */
    .word 0x48690000  /* mfv t1,S000 */
    .word 0xac890000  /* sw t1,0(a0) */
    .word 0xd0501000  /* vmfvc S000,S400: invalid control selector */
    .word 0x48690000  /* mfv t1,S000 */
    .word 0xac890004  /* sw t1,4(a0) */
    .word 0xd0507f00  /* vmfvc S000,(interlock): invalid control selector */
    .word 0x48690000  /* mfv t1,S000 */
    .word 0xac890008  /* sw t1,8(a0) */
    .word 0x03e00008  /* jr ra */
    .word 0x00000000  /* nop */
