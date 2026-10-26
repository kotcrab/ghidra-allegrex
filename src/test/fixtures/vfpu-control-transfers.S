/* Source-owned Allegrex VFPU control-register transfer baseline.
 * Entry: a0 points to 32 bytes writable memory; t0 = 0xffffffff.
 * All control transfers are followed by mfvc/mfv and stores for observation.
 * No game code or assets.
 */
    .text
    .set noreorder
    .globl vfpu_control_probe
vfpu_control_probe:
    .word 0x3c08ffff   /* lui t0,0xffff */
    .word 0x3508ffff   /* ori t0,t0,0xffff */
    .word 0x48e80080   /* mtvc t0,SPFX */
    .word 0x48690080   /* mfvc t1,SPFX */
    .word 0xac890000   /* sw t1,0(a0) */
    .word 0x48e80082   /* mtvc t0,DPFX */
    .word 0x48690082   /* mfvc t1,DPFX */
    .word 0xac890004   /* sw t1,4(a0) */
    .word 0x48e80083   /* mtvc t0,CC */
    .word 0x48690083   /* mfvc t1,CC */
    .word 0xac890008   /* sw t1,8(a0) */
    .word 0x48e80088   /* mtvc t0,RCX0 */
    .word 0x48690088   /* mfvc t1,RCX0 */
    .word 0xac89000c   /* sw t1,12(a0) */
    .word 0x48690085   /* mfvc t1,RSV5 -- before write */
    .word 0xac890010   /* sw t1,16(a0) */
    .word 0x48e80085   /* mtvc t0,RSV5 -- ignored on PPSSPP */
    .word 0x48690085   /* mfvc t1,RSV5 -- after write */
    .word 0xac890014   /* sw t1,20(a0) */
    .word 0x48e80000   /* mtv t0,S000 */
    .word 0xd0510001   /* vmtvc S000,TPFX */
    .word 0x48690081   /* mfvc t1,TPFX */
    .word 0xac890018   /* sw t1,24(a0) */
    .word 0xd0500100   /* vmfvc S000,TPFX -- ctrl selector bits 8..14 */
    .word 0x48690000   /* mfv t1,S000 */
    .word 0xac89001c   /* sw t1,28(a0) */
    .word 0x03e00008   /* jr ra */
    .word 0x00000000   /* nop */
