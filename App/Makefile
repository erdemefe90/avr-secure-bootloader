APP_BUILD := $(ROOT)/App/Release
APP_SOURCES := app_main circular_buffer timer uart
APP_OBJECTS := $(addprefix $(APP_BUILD)/,$(addsuffix .o,$(APP_SOURCES)))
APP_CFLAGS := -mmcu=atmega328p -DF_CPU=16000000UL -I$(ROOT)/Common -std=gnu99 -Os -flto -Wall -Wextra -ffunction-sections -fdata-sections -MMD -MP
APP_LDFLAGS := -mmcu=atmega328p -flto -Wl,--gc-sections,--relax -Wl,-Map=$(APP_BUILD)/App.map -Wl,-section-start=.data=0x800102 -Wl,-T$(ROOT)/App/App_Custom.ld

.PHONY: app
app: $(APP_BUILD)/App.hex

$(APP_BUILD)/%.o: $(ROOT)/App/%.c
	@mkdir -p $(APP_BUILD)
	$(AVR_CC) $(APP_CFLAGS) -c $< -o $@

$(APP_BUILD)/App.elf: $(APP_OBJECTS) $(ROOT)/App/App_Custom.ld
	$(AVR_CC) $(APP_OBJECTS) $(APP_LDFLAGS) -o $@
	$(AVR_SIZE) -A $@

$(APP_BUILD)/App.hex: $(APP_BUILD)/App.elf
	$(AVR_OBJCOPY) -O ihex -R .eeprom $< $@

-include $(APP_OBJECTS:.o=.d)
