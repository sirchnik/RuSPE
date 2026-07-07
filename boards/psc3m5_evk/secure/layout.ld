/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * Configuration for memory is for secure app with non-secure app
 * Documentation in ./mem-conf.md 
**/
MEMORY
{
	rom (rx)  : ORIGIN = 0x32000000, LENGTH = 0xFF00
	mcuboot (r) : ORIGIN = 0x3200FF00, LENGTH = 0x100
	nsc (rx)  : ORIGIN = 0x3201FF00, LENGTH = 0x100
  	ram (rwx) : ORIGIN = 0x34000000, LENGTH = 0x4000
}

INCLUDE spe_layout.ld
