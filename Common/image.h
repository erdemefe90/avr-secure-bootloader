#ifndef IMAGE_H_
#define IMAGE_H_

#include <stdint.h>

/* Public App/Bootloader contract for ATmega328P, 16 MHz. No private headers needed. */
#define IMAGE_MAGIC             0xefefefefu
#define BOOT_COMMAND            "BOOT\n"
#define BOOT_UART_BAUD          115200UL
#define BOOT_KEY                0xabcdu

/* Flash byte addresses. Application loads must end before BOOT_START_ADDRESS. */
#define IMAGE_HEADER_ADDRESS    0x0100u
#define BOOT_START_ADDRESS      0x7000u
/* AVR data-space address; GNU AVR linker scripts spell this as 0x800100. */
#define SHARED_AREA_ADDRESS     0x0100u

/* Declare exactly one object of each kind in each application. The linker must
 * KEEP these sections at the addresses below; attributes alone do not place them. */
#define IMAGE_HEADER_SECTION    __attribute__((used, section(".image_header")))
#define SHARED_AREA_SECTION     __attribute__((used, section(".shared_memory")))

/* Flash byte addresses: read with pgm_read_* / memcpy_P, not SRAM pointers. */
#define BOOT_INFO_ADDRESS       0x7f60u
#define BOOT_INFO_SIZE          26u
#define SERIAL_NUMBER_ADDRESS  0x7ff0u
/* C string: at most 15 UTF-8 bytes + NUL. Erased/unprovisioned flash is all 0xff. */
#define SERIAL_NUMBER_SIZE     16u

typedef struct __attribute__((packed)) {
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t sw_revision;
    uint16_t build_num;
    char compile_date[12];
    char compile_time[9];
} boot_info_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t hw_major;
    uint8_t hw_minor;
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t sw_revision;
    uint16_t build_num;
    char compile_date[12];
    char compile_time[9];
    char avr_gcc_version[6];
    uint16_t image_size;
    uint8_t nonce[12];
    uint8_t tag[16];
} image_header_t;

typedef struct __attribute__((packed)) {
    uint16_t boot_key;
} shared_area_t;

/* Standalone application integration (avr-gcc / Microchip Studio):
 *
 *   #include "image.h"
 *   volatile shared_area_t shared_area SHARED_AREA_SECTION;
 *   const image_header_t header IMAGE_HEADER_SECTION = {
 *       .magic = IMAGE_MAGIC, .hw_major = 3, .hw_minor = 1,
 *       .sw_major = 1, .sw_minor = 0, .sw_revision = 0, .build_num = 1,
 *       .compile_date = __DATE__, .compile_time = __TIME__,
 *       .avr_gcc_version = __VERSION__,
 *   };
 *
 * Application-owned HW/SW versions above are examples. Leave image_size, nonce
 * and tag zero: the release packager fills them. No device/signing key is needed
 * to compile the App. Bootloader firmware does not interpret HW versions.
 *
 * Linker requirements (these cannot be enforced by a C header):
 * - Keep reset/interrupt vectors at flash 0. Immediately after the vector table,
 *   advance to IMAGE_HEADER_ADDRESS, KEEP(*(.image_header)), then place remaining
 *   program/PROGMEM sections after the header (68 bytes, sizeof(image_header_t)).
 * - Limit ALL flash loads, including initialized .data, to [0, BOOT_START_ADDRESS).
 * - Place KEEP(*(.shared_memory)) at GNU AVR address 0x800100, NOLOAD, exactly
 *   sizeof(shared_area_t) = 2 bytes. Start .data at 0x800102, then .bss/.noinit;
 *   startup initialization must not clear the shared object. SRAM ends at 0x800900.
 * - ASSERT those addresses/sizes, flash load bounds and SRAM bounds in the linker.
 *   The repository's App_Custom.ld is a reference, not a bootloader dependency.
 *
 * On App startup clear shared_area.boot_key. Configure your own UART/RS485 driver
 * for BOOT_UART_BAUD, 8N1 (reference board: RX PD0, TX PD1, DE+/RE PD2).
 * On receipt of the exact sizeof(BOOT_COMMAND)-1 bytes, call bootloader_request().
 * This resets the MCU; it does not return or send an application-level ACK.
 * BOOTRST must be programmed and BOOTSZ1:0=00 for the installed bootloader.
 *
 * Read boot metadata/serial using <avr/pgmspace.h>, without bootloader symbols:
 *   boot_info_t info;
 *   char serial[SERIAL_NUMBER_SIZE];
 *   memcpy_P(&info, (const void *)BOOT_INFO_ADDRESS, sizeof(info));
 *   memcpy_P(serial, (const void *)SERIAL_NUMBER_ADDRESS, sizeof(serial));
 * Serial is erased (all 0xff) or a NUL-terminated string of 1..15 UTF-8 bytes.
 * Check for NUL within sizeof(serial) before using it as a string. BLB12 must
 * remain unprogrammed to permit application-side reads of these flash regions.
 */
#ifdef __AVR__
#include <avr/interrupt.h>
#include <avr/wdt.h>

static inline void __attribute__((noreturn)) bootloader_request(void)
{
    cli();
    ((volatile shared_area_t *)(uintptr_t)SHARED_AREA_ADDRESS)->boot_key = BOOT_KEY;
    wdt_enable(WDTO_15MS);
    for (;;) { }
}
#endif

#endif
