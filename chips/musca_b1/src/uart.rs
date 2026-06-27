// SPDX-FileCopyrightText: Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

use helpers::static_ref::StaticRef;
use tock_registers::{
    interfaces::{ReadWriteable, Readable, Writeable},
    register_bitfields, register_structs,
    registers::ReadWrite,
};

register_structs! {

    UartRegisters {
        /// Data Register, UARTDR
        (0x000 => uartdr: ReadWrite<u32, UARTDR::Register>),
        /// Receive Status Register/Error Clear Register, UARTRSR/UARTECR
        (0x004 => uartrsr: ReadWrite<u32, UARTRSR::Register>),
        (0x008 => _reserved0),
        /// Flag Register, UARTFR
        (0x018 => uartfr: ReadWrite<u32, UARTFR::Register>),
        (0x01C => _reserved1),
        /// IrDA Low-Power Counter Register, UARTILPR
        (0x020 => uartilpr: ReadWrite<u32, UARTILPR::Register>),
        /// Integer Baud Rate Register, UARTIBRD
        (0x024 => uartibrd: ReadWrite<u32, UARTIBRD::Register>),
        /// Fractional Baud Rate Register, UARTFBRD
        (0x028 => uartfbrd: ReadWrite<u32, UARTFBRD::Register>),
        /// Line Control Register, UARTLCR_H
        (0x02C => uartlcr_h: ReadWrite<u32, UARTLCR_H::Register>),
        /// Control Register, UARTCR
        (0x030 => uartcr: ReadWrite<u32, UARTCR::Register>),
        /// Interrupt FIFO Level Select Register, UARTIFLS
        (0x034 => uartifls: ReadWrite<u32, UARTIFLS::Register>),
        /// Interrupt Mask Set/Clear Register, UARTIMSC
        (0x038 => uartimsc: ReadWrite<u32, UARTIMSC::Register>),
        /// Raw Interrupt Status Register, UARTRIS
        (0x03C => uartris: ReadWrite<u32, UARTRIS::Register>),
        /// Masked Interrupt Status Register, UARTMIS
        (0x040 => uartmis: ReadWrite<u32, UARTMIS::Register>),
        /// Interrupt Clear Register, UARTICR
        (0x044 => uarticr: ReadWrite<u32, UARTICR::Register>),
        /// DMA Control Register, UARTDMACR
        (0x048 => uartdmacr: ReadWrite<u32, UARTDMACR::Register>),
        (0x04C => _reserved2),
        /// UARTPeriphID0 Register
        (0xFE0 => uartperiphid0: ReadWrite<u32, UARTPERIPHID0::Register>),
        /// UARTPeriphID1 Register
        (0xFE4 => uartperiphid1: ReadWrite<u32, UARTPERIPHID1::Register>),
        /// UARTPeriphID2 Register
        (0xFE8 => uartperiphid2: ReadWrite<u32, UARTPERIPHID2::Register>),
        /// UARTPeriphID3 Register
        (0xFEC => uartperiphid3: ReadWrite<u32, UARTPERIPHID3::Register>),
        /// UARTPCellID0 Register
        (0xFF0 => uartpcellid0: ReadWrite<u32, UARTPCELLID0::Register>),
        /// UARTPCellID1 Register
        (0xFF4 => uartpcellid1: ReadWrite<u32, UARTPCELLID1::Register>),
        /// UARTPCellID2 Register
        (0xFF8 => uartpcellid2: ReadWrite<u32, UARTPCELLID2::Register>),
        /// UARTPCellID3 Register
        (0xFFC => uartpcellid3: ReadWrite<u32, UARTPCELLID3::Register>),
        (0x1000 => @END),
    }
}
register_bitfields![u32,
UARTDR [
    /// Overrun error. This bit is set to 1 if data is received and the receive FIFO is already full. This is cleared to 0 once there is an empty space in the FIFO and a new character can be written to it.
    OE OFFSET(11) NUMBITS(1) [],
    /// Break error. This bit is set to 1 if a break condition was detected, indicating that the received data input was held LOW for longer than a full-word transmission time (defined as start, data, parity and stop bits). In FIFO mode, this error is associated with the character at the top of the FIFO. When a break occurs, only one 0 character is loaded into the FIFO. The next character is only enabled after the receive data input goes to a 1 (marking state), and the next valid start bit is received.
    BE OFFSET(10) NUMBITS(1) [],
    /// Parity error. When set to 1, it indicates that the parity of the received data character does not match the parity that the EPS and SPS bits in the Line Control Register, UARTLCR_H. In FIFO mode, this error is associated with the character at the top of the FIFO.
    PE OFFSET(9) NUMBITS(1) [],
    /// Framing error. When set to 1, it indicates that the received character did not have a valid stop bit (a valid stop bit is 1). In FIFO mode, this error is associated with the character at the top of the FIFO.
    FE OFFSET(8) NUMBITS(1) [],
    /// Receive (read) data character. Transmit (write) data character.
    DATA OFFSET(0) NUMBITS(8) []
],
UARTRSR [
    /// Overrun error. This bit is set to 1 if data is received and the FIFO is already full. This bit is cleared to 0 by a write to UARTECR. The FIFO contents remain valid because no more data is written when the FIFO is full, only the contents of the shift register are overwritten. The CPU must now read the data, to empty the FIFO.
    OE OFFSET(3) NUMBITS(1) [],
    /// Break error. This bit is set to 1 if a break condition was detected, indicating that the received data input was held LOW for longer than a full-word transmission time (defined as start, data, parity, and stop bits). This bit is cleared to 0 after a write to UARTECR. In FIFO mode, this error is associated with the character at the top of the FIFO. When a break occurs, only one 0 character is loaded into the FIFO. The next character is only enabled after the receive data input goes to a 1 (marking state) and the next valid start bit is received.
    BE OFFSET(2) NUMBITS(1) [],
    /// Parity error. When set to 1, it indicates that the parity of the received data character does not match the parity that the EPS and SPS bits in the Line Control Register, UARTLCR_H. This bit is cleared to 0 by a write to UARTECR. In FIFO mode, this error is associated with the character at the top of the FIFO.
    PE OFFSET(1) NUMBITS(1) [],
    /// Framing error. When set to 1, it indicates that the received character did not have a valid stop bit (a valid stop bit is 1). This bit is cleared to 0 by a write to UARTECR. In FIFO mode, this error is associated with the character at the top of the FIFO.
    FE OFFSET(0) NUMBITS(1) []
],
UARTFR [
    /// Ring indicator. This bit is the complement of the UART ring indicator, nUARTRI, modem status input. That is, the bit is 1 when nUARTRI is LOW.
    RI OFFSET(8) NUMBITS(1) [],
    /// Transmit FIFO empty. The meaning of this bit depends on the state of the FEN bit in the Line Control Register, UARTLCR_H. If the FIFO is disabled, this bit is set when the transmit holding register is empty. If the FIFO is enabled, the TXFE bit is set when the transmit FIFO is empty. This bit does not indicate if there is data in the transmit shift register.
    TXFE OFFSET(7) NUMBITS(1) [],
    /// Receive FIFO full. The meaning of this bit depends on the state of the FEN bit in the UARTLCR_H Register. If the FIFO is disabled, this bit is set when the receive holding register is full. If the FIFO is enabled, the RXFF bit is set when the receive FIFO is full.
    RXFF OFFSET(6) NUMBITS(1) [],
    /// Transmit FIFO full. The meaning of this bit depends on the state of the FEN bit in the UARTLCR_H Register. If the FIFO is disabled, this bit is set when the transmit holding register is full. If the FIFO is enabled, the TXFF bit is set when the transmit FIFO is full.
    TXFF OFFSET(5) NUMBITS(1) [],
    /// Receive FIFO empty. The meaning of this bit depends on the state of the FEN bit in the UARTLCR_H Register. If the FIFO is disabled, this bit is set when the receive holding register is empty. If the FIFO is enabled, the RXFE bit is set when the receive FIFO is empty.
    RXFE OFFSET(4) NUMBITS(1) [],
    /// UART busy. If this bit is set to 1, the UART is busy transmitting data. This bit remains set until the complete byte, including all the stop bits, has been sent from the shift register. This bit is set as soon as the transmit FIFO becomes non-empty, regardless of whether the UART is enabled or not.
    BUSY OFFSET(3) NUMBITS(1) [],
    /// Data carrier detect. This bit is the complement of the UART data carrier detect, nUARTDCD, modem status input. That is, the bit is 1 when nUARTDCD is LOW.
    DCD OFFSET(2) NUMBITS(1) [],
    /// Data set ready. This bit is the complement of the UART data set ready, nUARTDSR, modem status input. That is, the bit is 1 when nUARTDSR is LOW.
    DSR OFFSET(1) NUMBITS(1) [],
    /// Clear to send. This bit is the complement of the UART clear to send, nUARTCTS, modem status input. That is, the bit is 1 when nUARTCTS is LOW.
    CTS OFFSET(0) NUMBITS(1) []
],
UARTILPR [
    /// 8-bit low-power divisor value. These bits are cleared to 0 at reset.
    ILPDVSR OFFSET(0) NUMBITS(8) []
],
UARTIBRD [
    /// The integer baud rate divisor. These bits are cleared to 0 on reset.
    BAUD_DIVINT OFFSET(0) NUMBITS(16) []
],
UARTFBRD [
    /// The fractional baud rate divisor. These bits are cleared to 0 on reset.
    BAUD_DIVFRAC OFFSET(0) NUMBITS(6) []
],
UARTLCR_H [
    /// Stick parity select. 0 = stick parity is disabled 1 = either: * if the EPS bit is 0 then the parity bit is transmitted and checked as a 1 * if the EPS bit is 1 then the parity bit is transmitted and checked as a 0. This bit has no effect when the PEN bit disables parity checking and generation.
    SPS OFFSET(7) NUMBITS(1) [],
    /// Word length. These bits indicate the number of data bits transmitted or received in a frame as follows: b11 = 8 bits b10 = 7 bits b01 = 6 bits b00 = 5 bits.
    WLEN OFFSET(5) NUMBITS(2) [
        BITS_5 = 0b00,
        BITS_6 = 0b01,
        BITS_7 = 0b10,
        BITS_8 = 0b11,
    ],
    /// Enable FIFOs: 0 = FIFOs are disabled (character mode) that is, the FIFOs become 1-byte-deep holding registers 1 = transmit and receive FIFO buffers are enabled (FIFO mode).
    FEN OFFSET(4) NUMBITS(1) [],
    /// Two stop bits select. If this bit is set to 1, two stop bits are transmitted at the end of the frame. The receive logic does not check for two stop bits being received.
    STP2 OFFSET(3) NUMBITS(1) [],
    /// Even parity select. Controls the type of parity the UART uses during transmission and reception: 0 = odd parity. The UART generates or checks for an odd number of 1s in the data and parity bits. 1 = even parity. The UART generates or checks for an even number of 1s in the data and parity bits. This bit has no effect when the PEN bit disables parity checking and generation.
    EPS OFFSET(2) NUMBITS(1) [],
    /// Parity enable: 0 = parity is disabled and no parity bit added to the data frame 1 = parity checking and generation is enabled.
    PEN OFFSET(1) NUMBITS(1) [],
    /// Send break. If this bit is set to 1, a low-level is continually output on the UARTTXD output, after completing transmission of the current character. For the proper execution of the break command, the software must set this bit for at least two complete frames. For normal use, this bit must be cleared to 0.
    BRK OFFSET(0) NUMBITS(1) []
],
UARTCR [
    /// CTS hardware flow control enable. If this bit is set to 1, CTS hardware flow control is enabled. Data is only transmitted when the nUARTCTS signal is asserted.
    CTSEN OFFSET(15) NUMBITS(1) [],
    /// RTS hardware flow control enable. If this bit is set to 1, RTS hardware flow control is enabled. Data is only requested when there is space in the receive FIFO for it to be received.
    RTSEN OFFSET(14) NUMBITS(1) [],
    /// This bit is the complement of the UART Out2 (nUARTOut2) modem status output. That is, when the bit is programmed to a 1, the output is 0. For DTE this can be used as Ring Indicator (RI).
    OUT2 OFFSET(13) NUMBITS(1) [],
    /// This bit is the complement of the UART Out1 (nUARTOut1) modem status output. That is, when the bit is programmed to a 1 the output is 0. For DTE this can be used as Data Carrier Detect (DCD).
    OUT1 OFFSET(12) NUMBITS(1) [],
    /// Request to send. This bit is the complement of the UART request to send, nUARTRTS, modem status output. That is, when the bit is programmed to a 1 then nUARTRTS is LOW.
    RTS OFFSET(11) NUMBITS(1) [],
    /// Data transmit ready. This bit is the complement of the UART data transmit ready, nUARTDTR, modem status output. That is, when the bit is programmed to a 1 then nUARTDTR is LOW.
    DTR OFFSET(10) NUMBITS(1) [],
    /// Receive enable. If this bit is set to 1, the receive section of the UART is enabled. Data reception occurs for either UART signals or SIR signals depending on the setting of the SIREN bit. When the UART is disabled in the middle of reception, it completes the current character before stopping.
    RXE OFFSET(9) NUMBITS(1) [],
    /// Transmit enable. If this bit is set to 1, the transmit section of the UART is enabled. Data transmission occurs for either UART signals, or SIR signals depending on the setting of the SIREN bit. When the UART is disabled in the middle of transmission, it completes the current character before stopping.
    TXE OFFSET(8) NUMBITS(1) [],
    /// Loopback enable. If this bit is set to 1 and the SIREN bit is set to 1 and the SIRTEST bit in the Test Control Register, UARTTCR is set to 1, then the nSIROUT path is inverted, and fed through to the SIRIN path. The SIRTEST bit in the test register must be set to 1 to override the normal half-duplex SIR operation. This must be the requirement for accessing the test registers during normal operation, and SIRTEST must be cleared to 0 when loopback testing is finished. This feature reduces the amount of external coupling required during system test. If this bit is set to 1, and the SIRTEST bit is set to 0, the UARTTXD path is fed through to the UARTRXD path. In either SIR mode or UART mode, when this bit is set, the modem outputs are also fed through to the modem inputs. This bit is cleared to 0 on reset, to disable loopback.
    LBE OFFSET(7) NUMBITS(1) [],
    /// SIR low-power IrDA mode. This bit selects the IrDA encoding mode. If this bit is cleared to 0, low-level bits are transmitted as an active high pulse with a width of 3 / 16th of the bit period. If this bit is set to 1, low-level bits are transmitted with a pulse width that is 3 times the period of the IrLPBaud16 input signal, regardless of the selected bit rate. Setting this bit uses less power, but might reduce transmission distances.
    SIRLP OFFSET(2) NUMBITS(1) [],
    /// SIR enable: 0 = IrDA SIR ENDEC is disabled. nSIROUT remains LOW (no light pulse generated), and signal transitions on SIRIN have no effect. 1 = IrDA SIR ENDEC is enabled. Data is transmitted and received on nSIROUT and SIRIN. UARTTXD remains HIGH, in the marking state. Signal transitions on UARTRXD or modem status inputs have no effect. This bit has no effect if the UARTEN bit disables the UART.
    SIREN OFFSET(1) NUMBITS(1) [],
    /// UART enable: 0 = UART is disabled. If the UART is disabled in the middle of transmission or reception, it completes the current character before stopping. 1 = the UART is enabled. Data transmission and reception occurs for either UART signals or SIR signals depending on the setting of the SIREN bit.
    UARTEN OFFSET(0) NUMBITS(1) []
],
UARTIFLS [
    /// Receive interrupt FIFO level select. The trigger points for the receive interrupt are as follows: b000 = Receive FIFO becomes >= 1 / 8 full b001 = Receive FIFO becomes >= 1 / 4 full b010 = Receive FIFO becomes >= 1 / 2 full b011 = Receive FIFO becomes >= 3 / 4 full b100 = Receive FIFO becomes >= 7 / 8 full b101-b111 = reserved.
    RXIFLSEL OFFSET(3) NUMBITS(3) [
        FIFO_1_8 = 0b000,
        FIFO_1_4 = 0b001,
        FIFO_1_2 = 0b010,
        FIFO_3_4 = 0b011,
        FIFO_7_8 = 0b100,
    ],
    /// Transmit interrupt FIFO level select. The trigger points for the transmit interrupt are as follows: b000 = Transmit FIFO becomes <= 1 / 8 full b001 = Transmit FIFO becomes <= 1 / 4 full b010 = Transmit FIFO becomes <= 1 / 2 full b011 = Transmit FIFO becomes <= 3 / 4 full b100 = Transmit FIFO becomes <= 7 / 8 full b101-b111 = reserved.
    TXIFLSEL OFFSET(0) NUMBITS(3) []
],
UARTIMSC [
    /// Overrun error interrupt mask. A read returns the current mask for the UARTOEINTR interrupt. On a write of 1, the mask of the UARTOEINTR interrupt is set. A write of 0 clears the mask.
    OEIM OFFSET(10) NUMBITS(1) [],
    /// Break error interrupt mask. A read returns the current mask for the UARTBEINTR interrupt. On a write of 1, the mask of the UARTBEINTR interrupt is set. A write of 0 clears the mask.
    BEIM OFFSET(9) NUMBITS(1) [],
    /// Parity error interrupt mask. A read returns the current mask for the UARTPEINTR interrupt. On a write of 1, the mask of the UARTPEINTR interrupt is set. A write of 0 clears the mask.
    PEIM OFFSET(8) NUMBITS(1) [],
    /// Framing error interrupt mask. A read returns the current mask for the UARTFEINTR interrupt. On a write of 1, the mask of the UARTFEINTR interrupt is set. A write of 0 clears the mask.
    FEIM OFFSET(7) NUMBITS(1) [],
    /// Receive timeout interrupt mask. A read returns the current mask for the UARTRTINTR interrupt. On a write of 1, the mask of the UARTRTINTR interrupt is set. A write of 0 clears the mask.
    RTIM OFFSET(6) NUMBITS(1) [],
    /// Transmit interrupt mask. A read returns the current mask for the UARTTXINTR interrupt. On a write of 1, the mask of the UARTTXINTR interrupt is set. A write of 0 clears the mask.
    TXIM OFFSET(5) NUMBITS(1) [],
    /// Receive interrupt mask. A read returns the current mask for the UARTRXINTR interrupt. On a write of 1, the mask of the UARTRXINTR interrupt is set. A write of 0 clears the mask.
    RXIM OFFSET(4) NUMBITS(1) [],
    /// nUARTDSR modem interrupt mask. A read returns the current mask for the UARTDSRINTR interrupt. On a write of 1, the mask of the UARTDSRINTR interrupt is set. A write of 0 clears the mask.
    DSRMIM OFFSET(3) NUMBITS(1) [],
    /// nUARTDCD modem interrupt mask. A read returns the current mask for the UARTDCDINTR interrupt. On a write of 1, the mask of the UARTDCDINTR interrupt is set. A write of 0 clears the mask.
    DCDMIM OFFSET(2) NUMBITS(1) [],
    /// nUARTCTS modem interrupt mask. A read returns the current mask for the UARTCTSINTR interrupt. On a write of 1, the mask of the UARTCTSINTR interrupt is set. A write of 0 clears the mask.
    CTSMIM OFFSET(1) NUMBITS(1) [],
    /// nUARTRI modem interrupt mask. A read returns the current mask for the UARTRIINTR interrupt. On a write of 1, the mask of the UARTRIINTR interrupt is set. A write of 0 clears the mask.
    RIMIM OFFSET(0) NUMBITS(1) []
],
UARTRIS [
    /// Overrun error interrupt status. Returns the raw interrupt state of the UARTOEINTR interrupt.
    OERIS OFFSET(10) NUMBITS(1) [],
    /// Break error interrupt status. Returns the raw interrupt state of the UARTBEINTR interrupt.
    BERIS OFFSET(9) NUMBITS(1) [],
    /// Parity error interrupt status. Returns the raw interrupt state of the UARTPEINTR interrupt.
    PERIS OFFSET(8) NUMBITS(1) [],
    /// Framing error interrupt status. Returns the raw interrupt state of the UARTFEINTR interrupt.
    FERIS OFFSET(7) NUMBITS(1) [],
    /// Receive timeout interrupt status. Returns the raw interrupt state of the UARTRTINTR interrupt. a
    RTRIS OFFSET(6) NUMBITS(1) [],
    /// Transmit interrupt status. Returns the raw interrupt state of the UARTTXINTR interrupt.
    TXRIS OFFSET(5) NUMBITS(1) [],
    /// Receive interrupt status. Returns the raw interrupt state of the UARTRXINTR interrupt.
    RXRIS OFFSET(4) NUMBITS(1) [],
    /// nUARTDSR modem interrupt status. Returns the raw interrupt state of the UARTDSRINTR interrupt.
    DSRRMIS OFFSET(3) NUMBITS(1) [],
    /// nUARTDCD modem interrupt status. Returns the raw interrupt state of the UARTDCDINTR interrupt.
    DCDRMIS OFFSET(2) NUMBITS(1) [],
    /// nUARTCTS modem interrupt status. Returns the raw interrupt state of the UARTCTSINTR interrupt.
    CTSRMIS OFFSET(1) NUMBITS(1) [],
    /// nUARTRI modem interrupt status. Returns the raw interrupt state of the UARTRIINTR interrupt.
    RIRMIS OFFSET(0) NUMBITS(1) []
],
UARTMIS [
    /// Overrun error masked interrupt status. Returns the masked interrupt state of the UARTOEINTR interrupt.
    OEMIS OFFSET(10) NUMBITS(1) [],
    /// Break error masked interrupt status. Returns the masked interrupt state of the UARTBEINTR interrupt.
    BEMIS OFFSET(9) NUMBITS(1) [],
    /// Parity error masked interrupt status. Returns the masked interrupt state of the UARTPEINTR interrupt.
    PEMIS OFFSET(8) NUMBITS(1) [],
    /// Framing error masked interrupt status. Returns the masked interrupt state of the UARTFEINTR interrupt.
    FEMIS OFFSET(7) NUMBITS(1) [],
    /// Receive timeout masked interrupt status. Returns the masked interrupt state of the UARTRTINTR interrupt.
    RTMIS OFFSET(6) NUMBITS(1) [],
    /// Transmit masked interrupt status. Returns the masked interrupt state of the UARTTXINTR interrupt.
    TXMIS OFFSET(5) NUMBITS(1) [],
    /// Receive masked interrupt status. Returns the masked interrupt state of the UARTRXINTR interrupt.
    RXMIS OFFSET(4) NUMBITS(1) [],
    /// nUARTDSR modem masked interrupt status. Returns the masked interrupt state of the UARTDSRINTR interrupt.
    DSRMMIS OFFSET(3) NUMBITS(1) [],
    /// nUARTDCD modem masked interrupt status. Returns the masked interrupt state of the UARTDCDINTR interrupt.
    DCDMMIS OFFSET(2) NUMBITS(1) [],
    /// nUARTCTS modem masked interrupt status. Returns the masked interrupt state of the UARTCTSINTR interrupt.
    CTSMMIS OFFSET(1) NUMBITS(1) [],
    /// nUARTRI modem masked interrupt status. Returns the masked interrupt state of the UARTRIINTR interrupt.
    RIMMIS OFFSET(0) NUMBITS(1) []
],
UARTICR [
    /// Overrun error interrupt clear. Clears the UARTOEINTR interrupt.
    OEIC OFFSET(10) NUMBITS(1) [],
    /// Break error interrupt clear. Clears the UARTBEINTR interrupt.
    BEIC OFFSET(9) NUMBITS(1) [],
    /// Parity error interrupt clear. Clears the UARTPEINTR interrupt.
    PEIC OFFSET(8) NUMBITS(1) [],
    /// Framing error interrupt clear. Clears the UARTFEINTR interrupt.
    FEIC OFFSET(7) NUMBITS(1) [],
    /// Receive timeout interrupt clear. Clears the UARTRTINTR interrupt.
    RTIC OFFSET(6) NUMBITS(1) [],
    /// Transmit interrupt clear. Clears the UARTTXINTR interrupt.
    TXIC OFFSET(5) NUMBITS(1) [],
    /// Receive interrupt clear. Clears the UARTRXINTR interrupt.
    RXIC OFFSET(4) NUMBITS(1) [],
    /// nUARTDSR modem interrupt clear. Clears the UARTDSRINTR interrupt.
    DSRMIC OFFSET(3) NUMBITS(1) [],
    /// nUARTDCD modem interrupt clear. Clears the UARTDCDINTR interrupt.
    DCDMIC OFFSET(2) NUMBITS(1) [],
    /// nUARTCTS modem interrupt clear. Clears the UARTCTSINTR interrupt.
    CTSMIC OFFSET(1) NUMBITS(1) [],
    /// nUARTRI modem interrupt clear. Clears the UARTRIINTR interrupt.
    RIMIC OFFSET(0) NUMBITS(1) []
],
UARTDMACR [
    /// DMA on error. If this bit is set to 1, the DMA receive request outputs, UARTRXDMASREQ or UARTRXDMABREQ, are disabled when the UART error interrupt is asserted.
    DMAONERR OFFSET(2) NUMBITS(1) [],
    /// Transmit DMA enable. If this bit is set to 1, DMA for the transmit FIFO is enabled.
    TXDMAE OFFSET(1) NUMBITS(1) [],
    /// Receive DMA enable. If this bit is set to 1, DMA for the receive FIFO is enabled.
    RXDMAE OFFSET(0) NUMBITS(1) []
],
UARTPERIPHID0 [
    /// These bits read back as 0x11
    PARTNUMBER0 OFFSET(0) NUMBITS(8) []
],
UARTPERIPHID1 [
    /// These bits read back as 0x1
    DESIGNER0 OFFSET(4) NUMBITS(4) [],
    /// These bits read back as 0x0
    PARTNUMBER1 OFFSET(0) NUMBITS(4) []
],
UARTPERIPHID2 [
    /// This field depends on the revision of the UART: r1p0 0x0 r1p1 0x1 r1p3 0x2 r1p4 0x2 r1p5 0x3
    REVISION OFFSET(4) NUMBITS(4) [],
    /// These bits read back as 0x4
    DESIGNER1 OFFSET(0) NUMBITS(4) []
],
UARTPERIPHID3 [
    /// These bits read back as 0x00
    CONFIGURATION OFFSET(0) NUMBITS(8) []
],
UARTPCELLID0 [
    /// These bits read back as 0x0D
    UARTPCELLID0 OFFSET(0) NUMBITS(8) []
],
UARTPCELLID1 [
    /// These bits read back as 0xF0
    UARTPCELLID1 OFFSET(0) NUMBITS(8) []
],
UARTPCELLID2 [
    /// These bits read back as 0x05
    UARTPCELLID2 OFFSET(0) NUMBITS(8) []
],
UARTPCELLID3 [
    /// These bits read back as 0xB1
    UARTPCELLID3 OFFSET(0) NUMBITS(8) []
]
];

/// Number of stop bits to send after each word.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StopBits {
    /// Include one stop bit after each word.
    One = 1,
    /// Include two stop bits after each word.
    Two = 2,
}

/// Parity bit configuration.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Parity {
    /// No parity bits.
    None = 0,
    /// Add a parity bit to ensure an odd number of 1 bits in the word.
    Odd = 1,
    /// Add a parity bit to ensure an even number of 1 bits in the word.
    Even = 2,
}

/// Number of bits in each word.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Width {
    /// Six bits per word.
    Six = 6,
    /// Seven bits per word.
    Seven = 7,
    /// Eight bits per word.
    Eight = 8,
}

/// UART parameters for configuring the bus.
#[derive(Copy, Clone, Debug)]
pub struct Parameters {
    /// Baud rate in bit/s.
    pub baud_rate: u32,
    /// Number of bits per word.
    pub width: Width,
    /// Parity bit configuration.
    pub parity: Parity,
    /// Number of stop bits per word.
    pub stop_bits: StopBits,
    /// Whether UART flow control is enabled.
    pub hw_flow_control: bool,
}

const UART0_BASE_SEC: StaticRef<UartRegisters> =
    unsafe { StaticRef::new(0x50105000 as *const UartRegisters) };

const UART0_BASE_NSEC: StaticRef<UartRegisters> =
    unsafe { StaticRef::new(0x40105000 as *const UartRegisters) };

const UART1_BASE_SEC: StaticRef<UartRegisters> =
    unsafe { StaticRef::new(0x50106000 as *const UartRegisters) };

const UART1_BASE_NSEC: StaticRef<UartRegisters> =
    unsafe { StaticRef::new(0x40106000 as *const UartRegisters) };

pub struct UartMin {
    registers: StaticRef<UartRegisters>,
}

impl UartMin {
    pub const fn new_uart0_sec() -> Self {
        Self {
            registers: UART0_BASE_SEC,
        }
    }

    pub const fn new_uart1_sec() -> Self {
        Self {
            registers: UART1_BASE_SEC,
        }
    }

    pub const fn new_uart0_nsec() -> Self {
        Self {
            registers: UART0_BASE_NSEC,
        }
    }

    pub const fn new_uart1_nsec() -> Self {
        Self {
            registers: UART1_BASE_NSEC,
        }
    }

    pub fn enable(&self) {
        self.registers.uartcr.modify(UARTCR::UARTEN::SET);
    }

    pub fn disable(&self) {
        self.registers.uartcr.modify(UARTCR::UARTEN::CLEAR);
    }

    fn uart_is_writable(&self) -> bool {
        !self.registers.uartfr.is_set(UARTFR::TXFF)
    }

    fn uart_is_readable(&self) -> bool {
        !self.registers.uartfr.is_set(UARTFR::RXFE)
    }

    pub fn send_byte(&self, data: u8) {
        while !self.uart_is_writable() {}
        self.registers.uartdr.write(UARTDR::DATA.val(data as u32));
    }

    pub fn receive_byte(&self) -> u8 {
        while !self.uart_is_readable() {}
        self.registers.uartdr.read(UARTDR::DATA) as u8
    }

    pub fn configure(&self, params: Parameters, clock_freq: u32) {
        self.disable();
        self.registers.uartlcr_h.modify(UARTLCR_H::FEN::CLEAR);

        let baud_rate_div = 8 * clock_freq / params.baud_rate;
        let mut baud_ibrd = baud_rate_div >> 7;
        let mut baud_fbrd = (baud_rate_div & 0x7f).div_ceil(2);

        if baud_ibrd == 0 {
            baud_ibrd = 1;
            baud_fbrd = 0;
        } else if baud_ibrd >= 65535 {
            baud_ibrd = 65535;
            baud_fbrd = 0;
        }

        self.registers
            .uartibrd
            .write(UARTIBRD::BAUD_DIVINT.val(baud_ibrd));
        self.registers
            .uartfbrd
            .write(UARTFBRD::BAUD_DIVFRAC.val(baud_fbrd));

        self.registers.uartlcr_h.modify(UARTLCR_H::BRK::SET);
        // Configure the word length
        match params.width {
            Width::Six => self.registers.uartlcr_h.modify(UARTLCR_H::WLEN::BITS_6),
            Width::Seven => self.registers.uartlcr_h.modify(UARTLCR_H::WLEN::BITS_7),
            Width::Eight => self.registers.uartlcr_h.modify(UARTLCR_H::WLEN::BITS_8),
        }

        // Configure parity
        match params.parity {
            Parity::None => {
                self.registers.uartlcr_h.modify(UARTLCR_H::PEN::CLEAR);
                self.registers.uartlcr_h.modify(UARTLCR_H::EPS::CLEAR);
            }
            Parity::Odd => {
                self.registers.uartlcr_h.modify(UARTLCR_H::PEN::SET);
                self.registers.uartlcr_h.modify(UARTLCR_H::EPS::CLEAR);
            }
            Parity::Even => {
                self.registers.uartlcr_h.modify(UARTLCR_H::PEN::SET);
                self.registers.uartlcr_h.modify(UARTLCR_H::EPS::SET);
            }
        }

        // Set the stop bit length
        match params.stop_bits {
            StopBits::One => self.registers.uartlcr_h.modify(UARTLCR_H::STP2::CLEAR),
            StopBits::Two => self.registers.uartlcr_h.modify(UARTLCR_H::STP2::SET),
        }

        // Set flow control
        if params.hw_flow_control {
            self.registers.uartcr.modify(UARTCR::RTSEN::SET);
            self.registers.uartcr.modify(UARTCR::CTSEN::SET);
        } else {
            self.registers.uartcr.modify(UARTCR::RTSEN::CLEAR);
            self.registers.uartcr.modify(UARTCR::CTSEN::CLEAR);
        }
        self.registers.uartlcr_h.modify(UARTLCR_H::BRK::CLEAR);
        self.registers.uartlcr_h.modify(UARTLCR_H::FEN::CLEAR);

        self.registers
            .uartcr
            .modify(UARTCR::UARTEN::SET + UARTCR::TXE::SET + UARTCR::RXE::SET);
    }
}
