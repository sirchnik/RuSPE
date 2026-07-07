/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * Configuration for memory is for secure app with non-secure app (IPC model).
 * Services are embedded in the SPM binary and dispatched via SpmIpc.
**/
MEMORY
{
	rom (rx)  : ORIGIN = 0x32000000, LENGTH = 0x7F00
	mcuboot (r) : ORIGIN = 0x32007F00, LENGTH = 0x100
	nsc (rx)  : ORIGIN = 0x3201FF00, LENGTH = 0x100
	ram (rwx) : ORIGIN = 0x34000000, LENGTH = 0x2300
}

INCLUDE spe_layout.ld
