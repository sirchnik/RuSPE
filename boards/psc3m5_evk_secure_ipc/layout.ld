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
	rom (rx)  : ORIGIN = 0x32000000, LENGTH = 0x10000
	nsc (rx)  : ORIGIN = 0x32017F00, LENGTH = 0x100
	priv_ram (rwx) : ORIGIN = 0x34000000, LENGTH = 0x2F00
}

INCLUDE secure_layout.ld
