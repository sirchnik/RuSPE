/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Infineon Technologies AG 2026.                           */

/* Note: The device has to be provisioned using the edgeprotecttools first */

/**
 * Configuration for memory is for secure app with non-secure app
 * Documentation in ./mem-conf.md 
**/

MEMORY
{
  	rom (rx)  : ORIGIN = 0x22010100, LENGTH = 0x1FF00
	prog (rx) : ORIGIN = 0x22030000, LENGTH = 0x10000 /* dynamically/after-compilation inserted apps */
  	ram (rwx) : ORIGIN = 0x24004000, LENGTH = 0xB000
}

PAGE_SIZE = 4K;

INCLUDE tock_kernel_layout.ld
