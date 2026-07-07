/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

MEMORY
{
	rom (rx)  : ORIGIN = 0x10000000, LENGTH = 0xFFF00
	mcuboot (r) : ORIGIN = 0x100FFF00, LENGTH = 0x100
	nsc (rx)  : ORIGIN = 0x10100000, LENGTH = 0x2000
  	ram (rwx) : ORIGIN = 0x30000000, LENGTH = 0x30000
}

INCLUDE spe_layout.ld
