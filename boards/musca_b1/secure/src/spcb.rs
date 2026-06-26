pub fn enable_idau_nsc_code() {
    unsafe {
        const NSCCFG_ADDR: u32 = 0x50080014u32;
        let nsc_cfg = NSCCFG_ADDR as *mut u32;
        // Allows SAU to define the code region as a NSC
        *nsc_cfg |= 1;
    }
}

pub fn enable_uart1_ns() {
    unsafe {
        // APBNSPPCEXP1 is at offset 0x84 from SPCB base 0x50080000
        const APBNSPPCEXP1_ADDR: u32 = 0x50080084u32;
        let nsp_ppc_exp1 = APBNSPPCEXP1_ADDR as *mut u32;
        // WORKAROUND:
        // In datasheet Bit 5 controls UART0 security (1 = Non-Secure)
        // In reality it control UART1 somehow or just plain doesn't work idk.
        *nsp_ppc_exp1 |= 1 << 5;
    }
}
