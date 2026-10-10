#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <avr/io.h>
#include <avr/boot.h>
#include <avr/pgmspace.h>
#include <avr/wdt.h>
#include "aes.h"
#include "image.h"
#include "protocol.h"
#include "crc.h"
#include "device_key.h"

#define IMAGE_HEADER_ADDRESS 0x0100u
#define BOOT_START_ADDRESS   0x7000u
#define IMAGE_MAGIC          0xefefefefu
#define IMAGE_HW_ID          0x0301u
#define IMAGE_PAGE_SIZE      128u
#define IMAGE_HEADER_SIZE    68u
#define IMAGE_TAG_OFFSET     52u
#define IMAGE_HEADER_PAGE    (IMAGE_HEADER_ADDRESS / IMAGE_PAGE_SIZE)
#define SERIAL_PAGE_ADDRESS  (SERIAL_NUMBER_ADDRESS & ~(IMAGE_PAGE_SIZE - 1u))
#define SERIAL_PAGE_OFFSET   (SERIAL_NUMBER_ADDRESS - SERIAL_PAGE_ADDRESS)

typedef char image_header_size_check[(sizeof(image_header_t) == IMAGE_HEADER_SIZE) ? 1 : -1];
typedef char image_tag_offset_check[(offsetof(image_header_t, tag) == IMAGE_TAG_OFFSET) ? 1 : -1];
typedef char shared_area_size_check[(sizeof(shared_area_t) == 2) ? 1 : -1];
typedef char boot_info_size_check[(sizeof(boot_info_t) == BOOT_INFO_SIZE) ? 1 : -1];
typedef char serial_page_check[(SERIAL_PAGE_ADDRESS == 0x7f80u &&
                               SERIAL_PAGE_OFFSET + SERIAL_NUMBER_SIZE == IMAGE_PAGE_SIZE) ? 1 : -1];

const boot_info_t boot_info __attribute__((used, section(".boot_info"))) = {
    .sw_major = 1,
    .sw_minor = 1,
    .sw_revision = 0,
    .build_num = 1,
    .compile_date = __DATE__,
    .compile_time = __TIME__,
};

/* Provision through the serial writer or ISP; firmware updates never write this page. */
const uint8_t serial_number[SERIAL_NUMBER_SIZE]
    __attribute__((used, section(".serial_number"))) = { [0 ... SERIAL_NUMBER_SIZE - 1] = 0xff };

/* The production key is generated outside the repository. */
static const uint8_t root_key[16] PROGMEM = { DEVICE_KEY_BYTES };
volatile shared_area_t shared_area __attribute__((section(".shared_memory")));

static struct AES_ctx enc_ctx, mac_ctx;
static image_header_t target;
static uint8_t payload[MAX_PAYLOAD_SIZE];
static uint8_t command, payload_len;
static uint16_t next_page;
static uint8_t active;
static uint8_t finished, finish_wait;
static uint8_t current_valid;

/* ATmega328P SPM programs LB2/LB1. This protocol never programs BLB pairs.
 * Reject every other bit and the reserved LB2/LB1=01 result before SPM. */
static uint8_t write_locks(uint8_t mask)
{
    if (active || finished) return NACK_STATE;
    if (!mask || (mask & ~LOCK_PROGRAM_MASK) ||
        ((boot_lock_fuse_bits_get(GET_LOCK_BITS) & ~mask & 3u) == 1u)) return NACK_LOCK;
    boot_lock_bits_set(mask);
    boot_spm_busy_wait();
    return (boot_lock_fuse_bits_get(GET_LOCK_BITS) & mask) ? NACK_LOCK : 0;
}

static void uart_put(uint8_t value)
{
    while (!(UCSR0A & (1 << UDRE0))) wdt_reset();
    UDR0 = value;
}

static uint8_t uart_get(uint8_t *value, uint8_t timeout_ms)
{
    uint8_t elapsed = 0;
    TIFR0 = (1 << OCF0A);
    while (elapsed < timeout_ms) {
        if (UCSR0A & (1 << RXC0)) {
            *value = UDR0;
            return 1;
        }
        if (TIFR0 & (1 << OCF0A)) {
            TIFR0 = (1 << OCF0A);
            ++elapsed;
        }
        wdt_reset();
    }
    return 0;
}

static void send_packet(uint8_t cmd, const uint8_t *data, uint8_t len)
{
    uint16_t crc = 0xffff;
    uint8_t c;
    PORTD |= (1 << PD2);
    UCSR0A |= (1 << TXC0);
    c = STX; uart_put(c); crc = crc16_ccitt(crc, &c, 1);
    c = cmd; uart_put(c); crc = crc16_ccitt(crc, &c, 1);
    c = len; uart_put(c); crc = crc16_ccitt(crc, &c, 1);
    for (uint8_t i = 0; i < len; ++i) {
        c = data[i]; uart_put(c); crc = crc16_ccitt(crc, &c, 1);
    }
    uart_put((uint8_t)crc);
    uart_put((uint8_t)(crc >> 8));
    while (!(UCSR0A & (1 << TXC0))) wdt_reset();
    PORTD &= ~(1 << PD2);
}

/* 0: no packet, 1: valid packet, 2: malformed packet. */
static uint8_t receive_packet(void)
{
    uint8_t c, low;
    uint16_t crc = 0xffff;
    if (!uart_get(&c, 250)) return 0;
    if (c != STX) return 2;
    crc = crc16_ccitt(crc, &c, 1);
    if (!uart_get(&command, 20)) return 2;
    crc = crc16_ccitt(crc, &command, 1);
    if (!uart_get(&payload_len, 20) || payload_len > MAX_PAYLOAD_SIZE) return 2;
    crc = crc16_ccitt(crc, &payload_len, 1);
    for (uint8_t i = 0; i < payload_len; ++i) {
        if (!uart_get(&payload[i], 20)) return 2;
        crc = crc16_ccitt(crc, &payload[i], 1);
    }
    if (!uart_get(&low, 20) || !uart_get(&c, 20)) return 2;
    return crc == ((uint16_t)c << 8 | low) ? 1 : 2;
}

static void reply(uint8_t cmd, uint16_t seq, uint8_t reason)
{
    uint8_t data[3] = {(uint8_t)seq, (uint8_t)(seq >> 8), reason};
    send_packet(cmd, data, cmd == CMD_ACK ? 2 : 3);
}

static void init_crypto(void)
{
    uint8_t key[16], derived[16];
    for (uint8_t i = 0; i < 16; ++i) key[i] = pgm_read_byte(&root_key[i]);
    AES_init_ctx(&enc_ctx, key);
    memset(derived, 0x01, 16);
    AES_ECB_encrypt(&enc_ctx, derived);
    AES_init_ctx(&mac_ctx, derived);
    memset(derived, 0x02, 16);
    AES_ECB_encrypt(&enc_ctx, derived);
    AES_init_ctx(&enc_ctx, derived);
    memset(key, 0, sizeof(key));
    memset(derived, 0, sizeof(derived));
}

static uint8_t mac_state[16], mac_block[16], mac_used;

static void mac_start(void)
{
    memset(mac_state, 0, 16);
    mac_used = 0;
}

static void mac_add(uint8_t b)
{
    if (mac_used == 16) {
        for (uint8_t i = 0; i < 16; ++i) mac_state[i] ^= mac_block[i];
        AES_ECB_encrypt(&mac_ctx, mac_state);
        mac_used = 0;
    }
    mac_block[mac_used++] = b;
}

static void mac_bytes(const uint8_t *data, uint8_t len)
{
    for (uint8_t i = 0; i < len; ++i) mac_add(data[i]);
}

static void mac_double(uint8_t *block)
{
    uint8_t carry = block[0] >> 7;
    for (uint8_t i = 0; i < 15; ++i) block[i] = (block[i] << 1) | (block[i + 1] >> 7);
    block[15] <<= 1;
    if (carry) block[15] ^= 0x87;
}

static void mac_finish(uint8_t *tag)
{
    uint8_t subkey[16] = {0};
    AES_ECB_encrypt(&mac_ctx, subkey);
    mac_double(subkey);
    if (mac_used != 16) {
        mac_block[mac_used++] = 0x80;
        while (mac_used < 16) mac_block[mac_used++] = 0;
        mac_double(subkey);
    }
    for (uint8_t i = 0; i < 16; ++i) tag[i] = mac_state[i] ^ mac_block[i] ^ subkey[i];
    AES_ECB_encrypt(&mac_ctx, tag);
}

static uint8_t tag_matches(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    for (uint8_t i = 0; i < 16; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

static uint8_t header_valid(const image_header_t *h)
{
    return h->magic == IMAGE_MAGIC && h->hw_id == IMAGE_HW_ID &&
           h->image_size >= IMAGE_HEADER_ADDRESS + IMAGE_PAGE_SIZE &&
           h->image_size <= BOOT_START_ADDRESS &&
           (h->image_size % IMAGE_PAGE_SIZE) == 0;
}

static void read_header(image_header_t *h)
{
    uint8_t *p = (uint8_t *)h;
    for (uint8_t i = 0; i < IMAGE_HEADER_SIZE; ++i)
        p[i] = pgm_read_byte_near(IMAGE_HEADER_ADDRESS + i);
}

static uint8_t check_image(void)
{
    image_header_t h;
    uint8_t tag[16];
    read_header(&h);
    if (!header_valid(&h)) return 0;
    mac_start();
    mac_add('I');
    for (uint16_t addr = 0; addr < h.image_size; ++addr) {
        uint8_t b = (addr >= IMAGE_HEADER_ADDRESS + IMAGE_TAG_OFFSET &&
                     addr < IMAGE_HEADER_ADDRESS + IMAGE_HEADER_SIZE)
                    ? 0 : pgm_read_byte_near(addr);
        mac_add(b);
        if ((addr & 0x7f) == 0) wdt_reset();
    }
    mac_finish(tag);
    return tag_matches(tag, h.tag);
}

static void decrypt_page(uint16_t page, uint8_t *data)
{
    uint8_t block[16];
    for (uint8_t i = 0; i < 8; ++i) {
        memset(block, 0, sizeof(block));
        memcpy(block, target.nonce, sizeof(target.nonce));
        uint16_t count = (page << 3) + i;
        block[14] = count >> 8;
        block[15] = count;
        AES_ECB_encrypt(&enc_ctx, block);
        for (uint8_t j = 0; j < 16; ++j) data[i * 16 + j] ^= block[j];
    }
}

static void program_page(uint16_t page, const uint8_t *data)
{
    uint16_t addr = page * IMAGE_PAGE_SIZE;
    boot_page_erase(addr);
    boot_spm_busy_wait();
    for (uint8_t i = 0; i < IMAGE_PAGE_SIZE; i += 2)
        boot_page_fill(addr + i, (uint16_t)data[i] | ((uint16_t)data[i + 1] << 8));
    boot_page_write(addr);
    boot_spm_busy_wait();
    boot_rww_enable();
}

/* Request: expected current serial, followed by the new serial (16 bytes each). */
static uint8_t write_serial(void)
{
    if (active || finished) return NACK_STATE;
    if (!payload[SERIAL_NUMBER_SIZE] || payload[2u * SERIAL_NUMBER_SIZE - 1u]) return NACK_SIZE;
    /* A lost ACK must not erase/write the page again. */
    if (!memcmp_P(payload + SERIAL_NUMBER_SIZE, (const void *)SERIAL_NUMBER_ADDRESS,
                  SERIAL_NUMBER_SIZE)) return 0;
    if (memcmp_P(payload, (const void *)SERIAL_NUMBER_ADDRESS, SERIAL_NUMBER_SIZE))
        return NACK_STATE;
    if (!(boot_lock_fuse_bits_get(GET_LOCK_BITS) & LOCK_BOOT_WRITE)) return NACK_LOCK;
    memcpy(payload + SERIAL_PAGE_OFFSET, payload + SERIAL_NUMBER_SIZE, SERIAL_NUMBER_SIZE);
    for (uint8_t i = 0; i < SERIAL_PAGE_OFFSET; ++i)
        payload[i] = pgm_read_byte_near(SERIAL_PAGE_ADDRESS + i);
    program_page(SERIAL_PAGE_ADDRESS / IMAGE_PAGE_SIZE, payload);
    for (uint8_t i = 0; i < IMAGE_PAGE_SIZE; ++i)
        if (pgm_read_byte_near(SERIAL_PAGE_ADDRESS + i) != payload[i]) return NACK_IMAGE;
    return 0;
}

static uint8_t page_tag_valid(uint16_t page, const uint8_t *cipher, const uint8_t *tag)
{
    uint8_t actual[16];
    mac_start();
    mac_add('P');
    mac_bytes((const uint8_t *)&target, IMAGE_HEADER_SIZE);
    mac_add((uint8_t)page);
    mac_add((uint8_t)(page >> 8));
    mac_bytes(cipher, IMAGE_PAGE_SIZE);
    mac_finish(actual);
    return tag_matches(actual, tag);
}

static void send_header(void)
{
    image_header_t h;
    read_header(&h);
    if (!current_valid) memset(&h, 0, sizeof(h));
    send_packet(CMD_HEADER, (const uint8_t *)&h, sizeof(h));
}

static void send_info(void)
{
    uint8_t data[INFO_PAYLOAD_SIZE];
    memcpy_P(data, (const void *)BOOT_INFO_ADDRESS, BOOT_INFO_SIZE);
    memcpy_P(data + BOOT_INFO_SIZE, (const void *)SERIAL_NUMBER_ADDRESS, SERIAL_NUMBER_SIZE);
    data[BOOT_INFO_SIZE + SERIAL_NUMBER_SIZE] = boot_lock_fuse_bits_get(GET_LOW_FUSE_BITS);
    data[BOOT_INFO_SIZE + SERIAL_NUMBER_SIZE + 1] = boot_lock_fuse_bits_get(GET_HIGH_FUSE_BITS);
    data[BOOT_INFO_SIZE + SERIAL_NUMBER_SIZE + 2] = boot_lock_fuse_bits_get(GET_EXTENDED_FUSE_BITS);
    data[BOOT_INFO_SIZE + SERIAL_NUMBER_SIZE + 3] = boot_lock_fuse_bits_get(GET_LOCK_BITS);
    send_packet(CMD_INFO, data, sizeof(data));
}

static void goto_app(void)
{
    shared_area.boot_key = 0;
    wdt_disable();
    __asm__ __volatile__("jmp 0");
}

int main(void)
{
    uint8_t rc;
    uint16_t seq;
    wdt_enable(WDTO_8S);
    DDRD |= (1 << PD2) | (1 << PD1);
    PORTD &= ~(1 << PD2);
    UCSR0A = (1 << U2X0);
    UBRR0 = 16;
    UCSR0B = (1 << TXEN0) | (1 << RXEN0);
    TCCR0A = (1 << WGM01);
    TCCR0B = (1 << CS01) | (1 << CS00);
    OCR0A = 249;
    init_crypto();
    current_valid = check_image();
    if (shared_area.boot_key != BOOT_KEY && current_valid) goto_app();
    send_header();
    send_info();
    for (;;) {
        rc = receive_packet();
        if (!rc) {
            if (finished && ++finish_wait >= 40) goto_app();
            send_header();
            send_info();
            continue;
        }
        if (rc == 2) { reply(CMD_NACK, 0xffff, NACK_PACKET); continue; }
        if (command == CMD_BEGIN && payload_len == IMAGE_HEADER_SIZE) {
            if ((boot_lock_fuse_bits_get(GET_LOCK_BITS) & (LOCK_APP_WRITE | LOCK_APP_READ)) !=
                (LOCK_APP_WRITE | LOCK_APP_READ)) {
                reply(CMD_NACK, 0xffff, NACK_LOCK); continue;
            }
            memcpy(&target, payload, sizeof(target));
            if (!header_valid(&target)) { reply(CMD_NACK, 0xffff, NACK_SIZE); continue; }
            active = 1;
            finished = 0;
            next_page = 0;
            reply(CMD_ACK, 0xffff, 0);
        } else if (command == CMD_PAGE && payload_len == PAGE_PAYLOAD_SIZE) {
            seq = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
            if (!active || seq >= target.image_size / IMAGE_PAGE_SIZE ||
                (seq != next_page && !(next_page && seq == next_page - 1))) {
                reply(CMD_NACK, seq, NACK_STATE); continue;
            }
            if (!page_tag_valid(seq, &payload[2], &payload[2 + IMAGE_PAGE_SIZE])) {
                reply(CMD_NACK, seq, NACK_AUTH); continue;
            }
            if (seq == next_page) {
                decrypt_page(seq, &payload[2]);
                if (seq == IMAGE_HEADER_PAGE && memcmp(&payload[2], &target, IMAGE_HEADER_SIZE)) {
                    reply(CMD_NACK, seq, NACK_IMAGE); continue;
                }
                if (seq == 0) current_valid = 0;
                program_page(seq, &payload[2]);
                for (uint8_t i = 0; i < IMAGE_PAGE_SIZE; ++i) {
                    if (pgm_read_byte_near(seq * IMAGE_PAGE_SIZE + i) != payload[2 + i]) {
                        active = 0;
                        reply(CMD_NACK, seq, NACK_IMAGE);
                        goto next;
                    }
                }
                ++next_page;
            }
            reply(CMD_ACK, seq, 0);
        } else if (command == CMD_FINISH && payload_len == 2) {
            seq = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
            if (finished && seq == next_page) {
                finish_wait = 0;
                reply(CMD_ACK, seq, 0);
                continue;
            }
            if (!active || seq != next_page || next_page != target.image_size / IMAGE_PAGE_SIZE) {
                reply(CMD_NACK, seq, NACK_STATE); continue;
            }
            if (!check_image()) { active = 0; reply(CMD_NACK, seq, NACK_IMAGE); continue; }
            active = 0;
            finished = 1;
            current_valid = 1;
            finish_wait = 0;
            reply(CMD_ACK, seq, 0);
        } else if (command == CMD_INFO && payload_len == 0) {
            send_info();
        } else if (command == CMD_SERIAL) {
            rc = payload_len == 2u * SERIAL_NUMBER_SIZE ? write_serial() : NACK_SIZE;
            reply(rc ? CMD_NACK : CMD_ACK, SERIAL_SEQ, rc);
        } else if (command == CMD_LOCK && payload_len == 1) {
            rc = write_locks(payload[0]);
            reply(rc ? CMD_NACK : CMD_ACK, CONTROL_SEQ, rc);
        } else if (command == CMD_RESET && payload_len == 0) {
            if (check_image()) shared_area.boot_key = 0;
            wdt_enable(WDTO_15MS);
            for (;;) { }
        } else {
            reply(CMD_NACK, 0xffff, NACK_STATE);
        }
next:   wdt_reset();
    }
}
