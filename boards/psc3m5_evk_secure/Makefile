# Licensed under the Apache License, Version 2.0 or the MIT License.
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright Infineon Technologies AG 2026.

DEBUG ?= 0

ifeq ($(DEBUG), 1)
	BUILD_TYPE = debug
else
	BUILD_TYPE = release
endif

TARGET_DIR = ../../target
TARGET = thumbv8m.main-none-eabi
PLATFORM = psc3m5_evk_secure

# Define the path to the TBF file to flash an application
APP?=
SECURE_PROJ=$(TARGET_DIR)/$(TARGET)/$(BUILD_TYPE)/$(PLATFORM)
KERNEL=$(TARGET_DIR)/$(TARGET)/$(BUILD_TYPE)/psc3m5_evk-app.elf
SEC_KERNEL_MERGED=$(TARGET_DIR)/$(TARGET)/$(BUILD_TYPE)/psc3m5_evk_sec_merged.hex

OPENOCD_ROOT = /opt/ModusToolboxProgtools-1.7/openocd

.PHONY: install
install: flash

$(BUILD_TYPE):
ifeq ($(DEBUG), 1)
	cargo build
else
	cargo build --release
endif
	FEATURES=non_secure_tz $(MAKE) -C ../psc3m5_evk build-with-app APP=$(APP) DEBUG=$(DEBUG)
	arm-none-eabi-objcopy -O ihex $(KERNEL) $(KERNEL).hex
	arm-none-eabi-objcopy -O ihex $(SECURE_PROJ) $(SECURE_PROJ).hex
	uv run hexmerge.py --output=$(SEC_KERNEL_MERGED) $(SECURE_PROJ).hex $(KERNEL).hex --no-start-addr --overlap=ignore # different start addresses, so ignore overlaps
	@echo "Building secure project with tock"

all: $(BUILD_TYPE)

# run does not work with --binary-format hex, so only download for now
.PHONY: flash
flash: release
	probe-rs download --chip PSC3M5FDS2AFQ1 --binary-format hex $(SEC_KERNEL_MERGED)

.PHONY: program
program: build-with-app
	${OPENOCD_ROOT}/bin/openocd -f openocd.tcl $(OPENOCD_OPTIONS) -c "init; reset init; program $(SEC_KERNEL_MERGED); reset; shutdown"

   
   
