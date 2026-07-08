/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2026.                                  */

MEMORY
{
  rom (rx)  : ORIGIN = 0x00102000, LENGTH = 0x0007F000
  prog (rx) : ORIGIN = 0x00182000, LENGTH = 0x0007E000
  ram (rwx) : ORIGIN = 0x20030000, LENGTH = 0x00050000
}

PAGE_SIZE = 4K;

INCLUDE tock_kernel_layout.ld
