/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Infineon Technologies AG 2026.                           */

/**
 * Configuration for memory is for secure app with non-secure app
 * Documentation in ./mem-conf.md 
**/
MEMORY
{
	ROM (rx)  : ORIGIN = 0x32000000, LENGTH = 0x3000
  	RAM (rwx) : ORIGIN = 0x34000000, LENGTH = 0x1000
}

INCLUDE service_layout.ld
