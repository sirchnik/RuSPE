/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Infineon Technologies AG 2026.                           */

/**
 * Configuration for memory is for secure app with non-secure app (IPC model).
 * Services are embedded in the SPM binary and dispatched via SpmIpc.
**/
MEMORY
{
	rom (rx)  : ORIGIN = 0x32000000, LENGTH = 0x13F00
	nsc (rx)  : ORIGIN = 0x32013F00, LENGTH = 0x100
  	ram (rwx) : ORIGIN = 0x34000000, LENGTH = 0x10000
}

INCLUDE secure_layout.ld
