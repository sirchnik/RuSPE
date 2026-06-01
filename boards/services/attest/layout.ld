/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Infineon Technologies AG 2026.                           */

/**
 * Configuration for memory is for secure app with non-secure app
 * Documentation in ./mem-conf.md 
**/
MEMORY
{
	ROM (rx)  : ORIGIN = 0x32010000, LENGTH = 0x3F00
	RAM (rwx) : ORIGIN = 0x34002F00, LENGTH = 0x1100
}

INCLUDE ../service_layout.ld
