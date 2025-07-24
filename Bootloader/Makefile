# Project settings
TARGET = Bootloader
MCU = atmega328p
F_CPU = 16000000UL
LD_SCRIPT = Bootloader_Custom.ld
BUILD_DIR = Release

SRC = \
    boot_main.c \
    bootloader.c \
    uart.c \
    tiny-AES-c/aes.c \
    ../Common/crc.c

INCLUDES = \
    -I../Common \
    -I./tiny-AES-c

# Tools
CC = avr-gcc
OBJCOPY = avr-objcopy
OBJDUMP = avr-objdump
SIZE = avr-size
AVRDUDE = avrdude

PROGRAMMER = usbasp
CHIP = m328p

# Flags
CFLAGS = -mmcu=$(MCU) -DF_CPU=$(F_CPU) $(INCLUDES) -std=gnu99 -Wall -ffunction-sections -fdata-sections -fpack-struct -fshort-enums -funsigned-char -funsigned-bitfields -Os -g3
LDFLAGS = -mmcu=$(MCU) -Wl,-Map=$(BUILD_DIR)/$(TARGET).map -Wl,--start-group -Wl,-lm -Wl,--end-group -Wl,--gc-sections -Wl,-section-start=.text=0x7000 -Wl,-section-start=.data=0x800108 -Wl,-T$(LD_SCRIPT)

# Default target
default: all

all: $(BUILD_DIR)/$(TARGET).elf

# Flattened object file list
OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SRC)))

# Build ELF from objects
$(BUILD_DIR)/$(TARGET).elf: $(OBJ)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJ) $(LDFLAGS) -o $@
	$(OBJCOPY) -O ihex -R .eeprom $@ $(BUILD_DIR)/$(TARGET).hex
	$(OBJDUMP) -d $@ > $(BUILD_DIR)/$(TARGET).lst
	$(SIZE) -C $@
	@echo "Build finished."

# Compile each .c into .o (using matching full path)
define COMPILE_template
$(BUILD_DIR)/$(notdir $(1:.c=.o)): $(1)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $$< -o $$@
endef

$(foreach src,$(SRC),$(eval $(call COMPILE_template,$(src))))

clean:
	rm -rf $(BUILD_DIR)

flash:
	$(AVRDUDE) -c $(PROGRAMMER) -p $(CHIP) -D -U flash:w:$(BUILD_DIR)/$(TARGET).hex

.PHONY: clean all flash
