.DEFAULT_GOAL := all
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
AVR_CC ?= avr-gcc
AVR_OBJCOPY ?= avr-objcopy
AVR_SIZE ?= avr-size
PYTHON ?= python3
LOCAL_KEYS := $(ROOT)/.local
DEVICE_KEY_FILE ?= $(LOCAL_KEYS)/device_key.hex
SIGNING_KEY_FILE ?= $(LOCAL_KEYS)/signing_private.pem

$(LOCAL_KEYS)/.ready:
	$(PYTHON) $(ROOT)/Tools/ensure_keys.py $(LOCAL_KEYS)
	@touch $@

$(LOCAL_KEYS)/device_key.hex $(LOCAL_KEYS)/signing_private.pem $(LOCAL_KEYS)/signing_public.pem: $(LOCAL_KEYS)/.ready
	@test -f $@

include App/Makefile
include Bootloader/Makefile

.PHONY: all package clean test
all: app bootloader package

package: $(ROOT)/App/Release/App_encrypted.bin

test: bootloader
	$(PYTHON) -m unittest discover -s $(ROOT)/tests -v

$(ROOT)/App/Release/App_encrypted.bin: $(ROOT)/App/Release/App.hex $(DEVICE_KEY_FILE) $(SIGNING_KEY_FILE) $(ROOT)/Tools/encrypt_image.py $(ROOT)/Tools/image_format.py
	$(PYTHON) $(ROOT)/Tools/encrypt_image.py -f $< --device-key $(DEVICE_KEY_FILE) --signing-key $(SIGNING_KEY_FILE) -o $@

clean:
	rm -rf $(ROOT)/App/Release $(ROOT)/Bootloader/Release
