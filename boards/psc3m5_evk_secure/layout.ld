/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Infineon Technologies AG 2026.                           */

MEMORY
{
  	rom (rx)  : ORIGIN = 0x32000000, LENGTH = 0x20000
  	ram (rwx) : ORIGIN = 0x34000000, LENGTH = 0x10000
}

INCLUDE secure_layout.ld
