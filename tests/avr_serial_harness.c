/* Execute serial/lock handlers in AVR/QEMU with simulated flash/lock peripherals. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <avr/io.h>
#include <avr/boot.h>
#include <avr/pgmspace.h>

static uint8_t flash_page[128], simulated_locks = 0xff;
static uint8_t erase_count, outside_page, corrupt_write;
static uint8_t lock_count, ignore_lock_write;

static void lock_program(uint8_t mask)
{
    ++lock_count;
    if (!ignore_lock_write) simulated_locks &= ~mask;
}

static uint8_t flash_read(uint16_t addr)
{
    if (addr < 0x7f80 || addr >= 0x8000) { outside_page = 1; return 0; }
    return flash_page[addr - 0x7f80];
}

static int flash_compare(const void *ram, const void *flash, size_t len)
{
    const uint8_t *data = ram;
    for (size_t i = 0; i < len; ++i)
        if (data[i] != flash_read((uint16_t)flash + i)) return 1;
    return 0;
}

static void *flash_copy(void *ram, const void *flash, size_t len)
{
    uint8_t *data = ram;
    for (size_t i = 0; i < len; ++i) data[i] = flash_read((uint16_t)flash + i);
    return ram;
}

static void flash_erase(uint16_t addr)
{
    if (addr != 0x7f80) outside_page = 1;
    ++erase_count;
    memset(flash_page, 0xff, sizeof(flash_page));
}

static void flash_fill(uint16_t addr, uint16_t value)
{
    if (addr < 0x7f80 || addr >= 0x7fff) { outside_page = 1; return; }
    flash_page[addr - 0x7f80] = value;
    flash_page[addr - 0x7f80 + 1] = value >> 8;
}

static void flash_write(uint16_t addr)
{
    if (addr != 0x7f80) outside_page = 1;
    if (corrupt_write) flash_page[127] ^= 1;
}

#undef boot_lock_fuse_bits_get
#define boot_lock_fuse_bits_get(addr) (simulated_locks)
#undef boot_lock_bits_set
#define boot_lock_bits_set(mask) lock_program(mask)
#undef boot_page_erase
#define boot_page_erase(addr) flash_erase(addr)
#undef boot_page_fill
#define boot_page_fill(addr, value) flash_fill(addr, value)
#undef boot_page_write
#define boot_page_write(addr) flash_write(addr)
#undef boot_spm_busy_wait
#define boot_spm_busy_wait() ((void)0)
#undef boot_rww_enable
#define boot_rww_enable() ((void)0)
#undef pgm_read_byte_near
#define pgm_read_byte_near(addr) flash_read((uint16_t)(addr))
#define memcmp_P flash_compare
#define memcpy_P flash_copy
#define main firmware_main
#include "../Bootloader/bootloader.c"
#undef main

static void request(uint8_t old_byte, uint8_t new_byte)
{
    memset(payload, old_byte, 16);
    if (old_byte != 0xff) payload[15] = 0;
    memset(payload + 16, new_byte, 16);
    payload[31] = 0;
}

int main(void)
{
    uint8_t results[14];
    for (uint8_t i = 0; i < 112; ++i) flash_page[i] = i ^ 0x5a;
    memset(flash_page + 112, 0xff, 16);
    request(0xff, 0x23);
    results[0] = write_serial() == 0 && erase_count == 1 && !outside_page;
    results[1] = 1;
    for (uint8_t i = 0; i < 128; ++i)
        if (flash_page[i] != (i < 112 ? (i ^ 0x5a) : i == 127 ? 0 : 0x23)) results[1] = 0;
    request(0xff, 0x23); /* repeat after lost ACK, with stale expected value */
    results[2] = write_serial() == 0 && erase_count == 1;
    request(0xff, 0x24);
    results[3] = write_serial() == NACK_STATE && erase_count == 1;
    request(0x23, 0x24);
    simulated_locks = 0xef;
    results[4] = write_serial() == NACK_LOCK && erase_count == 1;
    simulated_locks = 0xff;
    active = 1;
    results[5] = write_serial() == NACK_STATE && erase_count == 1;
    active = 0;
    finished = 1;
    results[6] = write_serial() == NACK_STATE && erase_count == 1;
    finished = 0;
    payload[31] = 'A';
    results[8] = write_serial() == NACK_SIZE && erase_count == 1;
    request(0x23, 0x24);
    payload[16] = 0;
    results[9] = write_serial() == NACK_SIZE && erase_count == 1;
    request(0x23, 0x24);
    corrupt_write = 1;
    results[7] = write_serial() == NACK_IMAGE && erase_count == 2 && !outside_page;

    /* Exhaust all six physical bits and every possible wire mask. */
    results[10] = 1;
    for (uint8_t initial = 0; initial < 64; ++initial) {
        for (uint16_t mask = 0; mask < 256; ++mask) {
            simulated_locks = 0xc0 | initial;
            lock_count = 0;
            uint8_t target = simulated_locks & ~mask;
            uint8_t rejected = !mask || (mask & ~3u) || ((target & 3) == 1);
            uint8_t rc = write_locks(mask);
            if (rc != (rejected ? NACK_LOCK : 0) || lock_count != !rejected ||
                simulated_locks != (rejected ? (0xc0 | initial) : target)) results[10] = 0;
        }
    }
    simulated_locks = 0xff;
    lock_count = 0;
    active = 1;
    results[11] = write_locks(0x03) == NACK_STATE && !lock_count;
    active = 0;
    finished = 1;
    results[11] &= write_locks(0x03) == NACK_STATE && !lock_count;
    finished = 0;
    results[12] = write_locks(0x03) == 0 && simulated_locks == 0xfc;
    results[12] &= write_locks(0x03) == 0 && simulated_locks == 0xfc; /* lost ACK */
    simulated_locks = 0xff;
    ignore_lock_write = 1;
    results[13] = write_locks(1) == NACK_LOCK && simulated_locks == 0xff;
    ignore_lock_write = 0;
    results[13] &= write_locks(1) == 0 && simulated_locks == 0xfe;
    UCSR0A = (1 << U2X0);
    UBRR0 = 16;
    UCSR0B = (1 << TXEN0);
    for (uint8_t i = 0; i < sizeof(results); ++i) uart_put(results[i]);
    for (;;) { }
}
