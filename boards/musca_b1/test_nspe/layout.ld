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
  rom (rx)  : ORIGIN = 0x00102000, LENGTH = 0x000FE000
  ram (rwx) : ORIGIN = 0x20030000, LENGTH = 0x00050000
}

PAGE_SIZE = 4K;

INCLUDE test_nspe_layout.ld
