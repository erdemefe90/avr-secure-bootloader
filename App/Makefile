# Project settings
TARGET = App
MCU = atmega328p
F_CPU = 16000000UL
LD_SCRIPT = App_Custom.ld
BUILD_DIR = Release

SRC = \
    app_main.c \
    circular_buffer.c \
    gpio.c \
	timer.c \
	uart.c \
    ../Common/crc.c

INCLUDES = \
    -I../Common \

# Tools
CC = avr-gcc
OBJCOPY = avr-objcopy
OBJDUMP = avr-objdump
SIZE = avr-size
PYTHON = python3

PUBLIC_KEY = ../Tools/public_key.pem
ENCRYPT_SCRIPT = ../Tools/encrypt_image.py

# Flags
CFLAGS = -mmcu=$(MCU) -DF_CPU=$(F_CPU) $(INCLUDES) -std=gnu99 -Wall -ffunction-sections -fdata-sections -fpack-struct -fshort-enums -funsigned-char -funsigned-bitfields -Og -g2 -DNDEBUG
LDFLAGS = -mmcu=$(MCU) -Wl,-Map=$(BUILD_DIR)/$(TARGET).map -Wl,--start-group -Wl,-lm -Wl,--end-group -Wl,--gc-sections -Wl,-section-start=.data=0x800108 -Wl,-T$(LD_SCRIPT)

# Default target
default: all

all: $(BUILD_DIR)/$(TARGET).elf postbuild

# Flattened object file list
OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SRC)))

# Build ELF from objects
$(BUILD_DIR)/$(TARGET).elf: $(OBJ)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJ) $(LDFLAGS) -o $@
	$(OBJCOPY) -O ihex -R .eeprom $@ $(BUILD_DIR)/$(TARGET).hex
	$(OBJDUMP) -d $@ > $(BUILD_DIR)/$(TARGET).lst
	$(SIZE) -C $@

# Compile each .c into .o (using matching full path)
define COMPILE_template
$(BUILD_DIR)/$(notdir $(1:.c=.o)): $(1)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $$< -o $$@
endef

$(foreach src,$(SRC),$(eval $(call COMPILE_template,$(src))))

clean:
	rm -rf $(BUILD_DIR)

postbuild:
	$(PYTHON) $(ENCRYPT_SCRIPT) -f $(BUILD_DIR)/$(TARGET).hex -k $(PUBLIC_KEY)
	@echo "Build finished."

.PHONY: all clean postbuild




