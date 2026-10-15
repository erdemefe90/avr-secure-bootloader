/* Run production status/control transmitters with observable DE transitions. */
#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include <avr/boot.h>
#include <avr/pgmspace.h>
#include <util/delay.h>
#include "image.h"

static volatile uint8_t de_port;
static uint8_t previous_de, rising, falling, pin_error, flash_error;
static uint8_t guard_count, guard_ready;
static uint8_t uart_flags = (1 << UDRE0) | (1 << TXC0);
static uint16_t tx_count;
static const boot_info_t metadata = {1, 1, 0, 1, "Oct 11 2026", "12:34:56"};

static void native_uart_init(void)
{
    UCSR0A = (1 << U2X0);
    UBRR0 = 16;
    UCSR0B = (1 << TXEN0);
}

static void native_put(uint8_t byte)
{
    while (!(UCSR0A & (1 << UDRE0))) { }
    UDR0 = byte;
}

static volatile uint8_t *direction_register(void)
{
    uint8_t level = !!(de_port & (1 << PD2));
    if (level != previous_de) {
        guard_ready = 0;
        if (level) ++rising; else ++falling;
        previous_de = level;
    }
    return &de_port;
}

static void observed_guard(uint16_t usec)
{
    direction_register();
    if (!(de_port & (1 << PD2)) || usec != 200) pin_error = 1;
    guard_ready = 1;
    ++guard_count;
}

static volatile uint8_t *observed_uart_data(void)
{
    direction_register();
    if (!(de_port & (1 << PD2)) || !guard_ready) pin_error = 1;
    ++tx_count;
    while (!(UCSR0A & (1 << UDRE0))) { }
    return &UDR0;
}

static uint8_t header_read(uint16_t addr)
{
    if (addr < 0x100 || addr >= 0x100 + sizeof(image_header_t)) flash_error = 1;
    return addr - 0x100;
}

static void *flash_copy(void *dest, const void *src, size_t len)
{
    uint16_t addr = (uint16_t)src;
    if (addr == BOOT_INFO_ADDRESS && len == sizeof(metadata))
        return memcpy(dest, &metadata, len);
    if (addr == SERIAL_NUMBER_ADDRESS && len == SERIAL_NUMBER_SIZE)
        return memset(dest, 0xff, len);
    if (addr == 0x100 && len == sizeof(image_header_t)) {
        uint8_t *bytes = dest;
        for (uint8_t i = 0; i < len; ++i) bytes[i] = header_read(addr + i);
        return dest;
    }
    flash_error = 1;
    return memset(dest, 0, len);
}

/* QEMU supplies the UART bytes; GPIO, flash metadata and TXC are modeled. */
#undef PORTD
#define PORTD (*direction_register())
#undef UCSR0A
#define UCSR0A uart_flags
#undef UDR0
#define UDR0 (*observed_uart_data())
#undef pgm_read_byte_near
#define pgm_read_byte_near(addr) header_read((uint16_t)(addr))
#undef boot_lock_fuse_bits_get
#define boot_lock_fuse_bits_get(addr) 0xff
#define memcpy_P flash_copy
#define _delay_us(usec) observed_guard((uint16_t)(usec))
#define main firmware_main
#include "../Bootloader/bootloader.c"
#undef main

static uint8_t burst_complete(uint16_t bytes)
{
    direction_register();
    uint8_t ok = rising == 1 && falling == 1 && guard_count == 1 &&
                 de_port == (1 << PD7) && tx_count == bytes && !pin_error;
    rising = falling = 0;
    guard_count = 0;
    tx_count = 0;
    return ok;
}

int main(void)
{
    uint8_t results[6];
    image_header_t h = {.magic = IMAGE_MAGIC, .hw_major = 3,
                        .hw_minor = 1, .image_size = 3 * SPM_PAGESIZE};
    de_port = (1 << PD7); /* An unrelated pin must be preserved. */
    native_uart_init();
    current_valid = 0;
    send_status();
    results[0] = burst_complete(124);
    current_valid = 1;
    send_status();
    results[1] = burst_complete(124);
    send_info();
    results[2] = burst_complete(51);
    reply(CMD_ACK, 0xfffe, 0);
    results[3] = burst_complete(7);
    reply(CMD_NACK, 3, NACK_PACKET);
    results[4] = burst_complete(8) && !flash_error;
    results[5] = header_valid(&h);
    /* Every HW byte pair is opaque metadata to the bootloader. */
    for (uint16_t major = 0; major <= UINT8_MAX; ++major) {
        for (uint16_t minor = 0; minor <= UINT8_MAX; ++minor) {
            h.hw_major = major;
            h.hw_minor = minor;
            if (!header_valid(&h)) results[5] = 0;
        }
    }
    h.magic ^= 1;
    results[5] &= !header_valid(&h);
    h.magic = IMAGE_MAGIC;
    h.image_size = IMAGE_HEADER_ADDRESS;
    results[5] &= !header_valid(&h);
    h.image_size = BOOT_START_ADDRESS + SPM_PAGESIZE;
    results[5] &= !header_valid(&h);
    h.image_size = 3 * SPM_PAGESIZE + 1;
    results[5] &= !header_valid(&h);
    for (uint8_t i = 0; i < sizeof(results); ++i) native_put(results[i]);
    for (;;) { }
}
