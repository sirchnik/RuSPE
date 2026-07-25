/*
 * SPDX-FileCopyrightText: Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 */

ENTRY(sec_initialize_ram_jump_to_main)

SECTIONS
{
	.mcuboot :
	{
		KEEP(*(.mcuboot))
	} > mcuboot

	.text :
	{
        . = ALIGN(4);
        _textstart = .;     /* Symbol expected by some MS build toolchains */
        _stext = .;         /* First of standard s,e (start/end) pair */

        /* Place vector table at the beginning of ROM.
         *
         * The first 16 entries in the ARM vector table are defined by ARM and
         * are common among all ARM chips. The remaining entries are
         * chip-specific and are defined in the separate .irqs section.
         *
         * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0553a/BABIFJFG.html
         */
		KEEP(*(.vectors .vectors.*))
		KEEP(*(.irqs))
        /* .text and .rodata hold most program code and immutable constants.
         * .gnu.linkonce hold C++ elements with vague linkage.
         * https://gcc.gnu.org/onlinedocs/gcc/Vague-Linkage.html
         */
        *(.text .text.* .gnu.linkonce.t.*)

        _srodata = .;
        *(.rodata .rodata.* .gnu.linkonce.r.*)

        /* C++ exception unwinding information */
        *(.ARM.extab* .gnu.linkonce.armextab.*)

        /* glue_7 and glue_7t hold helper functions emitted by the compiler to
         * support interworking (linking between functions in ARM and THUMB
         * mode). Note that Cortex-M's do not support ARM mode, but this is left
         * here to ease future portability.
         */
        *(.glue_7t) *(.glue_7)


        /* Constructor and destructor sections:
         *
         * - init/fini
         *    Defined by ELF as sections that hold `process
         *    initialization/termination code`
         * - {pre}{init/fini}_array_{start/end}
         *    Symbols used by the C runtime for initialization / termination
         * - ctors/dtors
         *    Symbols used by the C++ runtime for initialization / termination
         */
        . = ALIGN(4);
        KEEP(*(.init))
        . = ALIGN(4);
        __preinit_array_start = .;
        KEEP(*(.preinit_array))
        __preinit_array_end = .;

        . = ALIGN(4);
        __init_array_start = .;
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        __init_array_end = .;

        . = ALIGN(4);
        KEEP(*crtbegin.o(.ctors))
        KEEP(*(EXCLUDE_FILE (*crtend.o) .ctors))
        KEEP(*(SORT(.ctors.*)))
        KEEP(*crtend.o(.ctors))

        . = ALIGN(4);
        KEEP(*(.fini))

        . = ALIGN(4);
        __fini_array_start = .;
        KEEP(*(.fini_array))
        KEEP(*(SORT(.fini_array.*)))
        __fini_array_end = .;

        KEEP(*crtbegin.o(.dtors))
        KEEP(*(EXCLUDE_FILE (*crtend.o) .dtors))
        KEEP(*(SORT(.dtors.*)))
        KEEP(*crtend.o(.dtors))
        /* End constructor/destructor */
    } > rom


    /* ARM Exception support
     *
     * This contains compiler-generated support for unwinding the stack,
     * consisting of key-value pairs of function addresses and information on
     * how to unwind stack frames.
     * https://wiki.linaro.org/KenWerner/Sandbox/libunwind?action=AttachFile&do=get&target=libunwind-LDS.pdf
     *
     * .ARM.exidx is sorted, so has to go in its own output section.
     */
    PROVIDE_HIDDEN(__exidx_start = .);
    .ARM.exidx :
    {
        /* (C++) Index entries for section unwinding */
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > rom
    PROVIDE_HIDDEN(__exidx_end = .);

    /* Mark the end of static elements */
    . = ALIGN(4);
    _erodata = .;
    _etext = .;
    _textend = .;   /* alias for _etext expected by some MS toolchains */

    /* ### .gnu.sgstubs
    This section contains the TrustZone-M veneers put there by the Arm GNU linker. */
    /* Security Attribution Unit blocks must be 32 bytes aligned. */
    /* Note that this pads the FLASH usage to 32 byte alignment. */
    .gnu.sgstubs ORIGIN(nsc) : ALIGN(32)
    {
        . = ALIGN(32);
        __veneer_base = .;
        *(.gnu.sgstubs*)
        . = ALIGN(32);
    } > nsc 
    /* Place `__veneer_limit` outside the `.gnu.sgstubs` section because veneers are
    * always inserted last in the section, which would otherwise be _after_ the `__veneer_limit` symbol.
    */
    . = ALIGN(32);
    __veneer_limit = .;
    ASSERT(__veneer_limit <= ORIGIN(nsc) + LENGTH(nsc), "CMSE veneers exceed NSC region")

    /* Kernel data that must be relocated. This is program data that is
     * expected to live in SRAM, but is initialized with a value. This data is
     * physically placed into flash and copied into SRAM during startup. The
     * symbols here are defined with addresses in SRAM.
     */
    .relocate : AT (_etext)
    {
        . = ALIGN(4);
        _srelocate = .;

        *(.ramfunc .ramfunc.*);
        *(.sdata .sdata.* .gnu.linkonce.r.*)
        *(.data .data.*);

        . = ALIGN(4);
        _erelocate = .;
    } > ram

	.bss (NOLOAD) :
	{
		. = ALIGN(4);
		_szero = .;
		*(.bss .bss.*)
		*(COMMON)
		. = ALIGN(4);
		_ezero = .;
	} > ram

        /* No fixed stack reservation: stack starts after static RAM sections and
         * grows down from the top of RAM.
         */
        . = ALIGN(8);
        _sstack = .;
        _estack = ORIGIN(ram) + LENGTH(ram);
        ASSERT(_sstack <= _estack, "RAM overflow: no space left for stack")
}
