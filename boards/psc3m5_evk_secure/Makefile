# Licensed under the Apache License, Version 2.0 or the MIT License.
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright Infineon Technologies AG 2026.

DEBUG ?= 0

ifeq ($(DEBUG), 1)
	BUILD_TYPE = debug
else
	BUILD_TYPE = release
endif

TOCK_ROOT_DIRECTORY = ../..
TARGET = thumbv8m.main-none-eabi
PLATFORM = psc3m5_evk_secure

# Define the path to the TBF file to flash an application
APP?=
SECURE_PROJ=$(TOCK_ROOT_DIRECTORY)/target/$(TARGET)/$(BUILD_TYPE)/$(PLATFORM)
KERNEL=$(TOCK_ROOT_DIRECTORY)/target/$(TARGET)/$(BUILD_TYPE)/psc3m5_evk
SEC_KERNEL_MERGED=$(TOCK_ROOT_DIRECTORY)/target/$(TARGET)/$(BUILD_TYPE)/psc3m5_evk_sec_merged.hex

OPENOCD_ROOT = /opt/ModusToolboxProgtools-1.7/openocd

# install: flash
# .PHONY: install

debug: $(BUILD_TYPE)
release: $(BUILD_TYPE)

$(BUILD_TYPE):
ifeq ($(DEBUG), 1)
	cargo b
else
	cargo b --release
endif
	$(MAKE) -C ../psc3m5_evk APP=$(APP) DEBUG=$(DEBUG)
	arm-none-eabi-objcopy -O ihex $(KERNEL) $(KERNEL).hex
	arm-none-eabi-objcopy -O ihex $(SECURE_PROJ) $(SECURE_PROJ).hex
	uv run hexmerge.py --output=$(SEC_KERNEL_MERGED) $(SECURE_PROJ).hex $(KERNEL).hex --no-start-addr --overlap=ignore # different start addresses, so ignore overlaps
	@echo "Building secure project with tock"

all: $(BUILD_TYPE)

# .PHONY: flash
# flash: build-with-app
# 	probe-rs run --chip PSC3M5FDS2AFQ1 $(KERNEL_WITH_APP)

# .PHONY: program
# program: build-with-app
# 	${OPENOCD_ROOT}/bin/openocd -f openocd.tcl $(OPENOCD_OPTIONS) -c "init; reset init; program $(KERNEL_WITH_APP); reset; shutdown"

   
   
