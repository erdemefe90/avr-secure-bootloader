BOOT_BUILD := $(ROOT)/Bootloader/Release
BOOT_OBJECTS := $(BOOT_BUILD)/bootloader.o $(BOOT_BUILD)/aes.o $(BOOT_BUILD)/crc.o
BOOT_CFLAGS := -mmcu=atmega328p -DF_CPU=16000000UL -DCBC=0 -DCTR=0 -DECB=1 -I$(ROOT)/Common -I$(ROOT)/Bootloader/tiny-AES-c -I$(BOOT_BUILD) -std=gnu99 -Os -flto -Wall -Wextra -ffunction-sections -fdata-sections -MMD -MP
BOOT_LDFLAGS := -mmcu=atmega328p -flto -Wl,--gc-sections,--relax -Wl,-Map=$(BOOT_BUILD)/Bootloader.map -Wl,-section-start=.data=0x800102 -Wl,-T$(ROOT)/Bootloader/Bootloader_Custom.ld

.PHONY: bootloader
bootloader: $(BOOT_BUILD)/Bootloader.hex

$(BOOT_BUILD)/device_key.h: $(DEVICE_KEY_FILE) $(ROOT)/Tools/key_header.py
	@mkdir -p $(BOOT_BUILD)
	$(PYTHON) $(ROOT)/Tools/key_header.py $< $@

$(BOOT_BUILD)/bootloader.o: $(ROOT)/Bootloader/bootloader.c $(BOOT_BUILD)/device_key.h
	$(AVR_CC) $(BOOT_CFLAGS) -c $< -o $@

$(BOOT_BUILD)/aes.o: $(ROOT)/Bootloader/tiny-AES-c/aes.c
	@mkdir -p $(BOOT_BUILD)
	$(AVR_CC) $(BOOT_CFLAGS) -c $< -o $@

$(BOOT_BUILD)/crc.o: $(ROOT)/Bootloader/crc.c
	@mkdir -p $(BOOT_BUILD)
	$(AVR_CC) $(BOOT_CFLAGS) -c $< -o $@

$(BOOT_BUILD)/Bootloader.elf: $(BOOT_OBJECTS) $(ROOT)/Bootloader/Bootloader_Custom.ld
	$(AVR_CC) $(BOOT_OBJECTS) $(BOOT_LDFLAGS) -o $@
	$(AVR_SIZE) -A $@

$(BOOT_BUILD)/Bootloader.hex: $(BOOT_BUILD)/Bootloader.elf
	$(AVR_OBJCOPY) -O ihex -R .eeprom $< $@

-include $(BOOT_OBJECTS:.o=.d)
