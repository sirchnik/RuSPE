/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

/* Note: The device has to be provisioned using the edgeprotecttools first */

/**
 * Configuration for memory is for secure app with non-secure app
 * Documentation in ./mem-conf.md 
**/

MEMORY
{
	rom (rx)  : ORIGIN = 0x22018000, LENGTH = 0x1C000
	prog (rx) : ORIGIN = 0x22034000, LENGTH = 0xC000 /* dynamically/after-compilation inserted apps */
	 ram (rwx) : ORIGIN = 0x24005900, LENGTH = 0x9000
}

PAGE_SIZE = 4K;

INCLUDE tock_kernel_layout.ld
