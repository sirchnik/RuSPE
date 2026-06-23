/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

MEMORY
{
	rom (rx)  : ORIGIN = 0x10000000, LENGTH = 0x100000
	nsc (rx)  : ORIGIN = 0x10100000, LENGTH = 0x100
  	ram (rwx) : ORIGIN = 0x30000000, LENGTH = 0x30000
}

INCLUDE ../../shared/linker/spe_layout.ld
