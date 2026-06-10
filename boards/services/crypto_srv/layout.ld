/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * Configuration for memory is for secure app with non-secure app
 * Documentation in ./mem-conf.md
**/
MEMORY
{
    ROM (rx)  : ORIGIN = 0x32010000, LENGTH = 0x3F00
    RAM (rwx) : ORIGIN = 0x34002F00, LENGTH = 0x1100
}

INCLUDE ../shared/service_layout.ld
