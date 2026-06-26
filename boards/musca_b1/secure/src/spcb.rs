pub fn enable_idau_nsc_code() {
    unsafe {
        const NSCCFG_ADDR: u32 = 0x50080014u32;
        let nsc_cfg = NSCCFG_ADDR as *mut u32;
        // Allows SAU to define the code region as a NSC
        *nsc_cfg |= 1;
    }
}

pub fn enable_uart0_ns() {
    unsafe {
        // APB_PPCEXP2 is at offset 0x78 from SPCB base 0x50080000
        const APB_PPCEXP2_ADDR: u32 = 0x50080078u32;
        let ppc_exp2 = APB_PPCEXP2_ADDR as *mut u32;
        // Bit 0 controls UART0 security (1 = Non-Secure)
        *ppc_exp2 |= 1;
    }
}
