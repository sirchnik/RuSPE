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
	rom (rx)  : ORIGIN = 0x22020000, LENGTH = 0x16000
	 ram (rwx) : ORIGIN = 0x24005900, LENGTH = 0x9000
}

PAGE_SIZE = 4K;

INCLUDE test_nspe_layout.ld
