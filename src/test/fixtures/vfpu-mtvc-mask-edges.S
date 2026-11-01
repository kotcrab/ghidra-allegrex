/* Source-owned mtvc selector-boundary fixture. Input t0 holds any value. */
    .text
    .set noreorder
    .word 0x48e80081  /* mtvc t0,TPFX: 20-bit mask */
    .word 0x48e80084  /* mtvc t0,INF4: full write */
    .word 0x48e80086  /* mtvc t0,RSV6: read only */
    .word 0x48e80087  /* mtvc t0,REV: read only */
    .word 0x48e8008f  /* mtvc t0,RCX7: masked + forced upper bits */
    .word 0x48e80090  /* mtvc t0,S400: invalid control selector */
    .word 0x48e800ff  /* mtvc t0,(interlock): invalid control selector */
