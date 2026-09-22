#include <string.h>
#include <avr/boot.h>
#include <util/delay.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>
#include "aes.h"
#include "image.h"
#include "crc.h"
#include "bootloader.h"
#include "uart.h"

#define USE_NONCE 1
#define PKT_HEADER_LEN 3 

#define BOOT_CMD_HEADER         0xb0
#define BOOT_CMD_INFO           0xb1
#define BOOT_CMD_FLASH          0xb3
#define BOOT_CMD_ACK            0xb5
#define BOOT_CMD_NACK           0xb6
#define BOOT_CMD_RESET          0xb7

extern volatile shared_memory_t shared_area __attribute__((section(".shared_memory")));
extern volatile uint32_t tick;

static struct AES_ctx aes_ctx;
static const uint8_t aes_key[16] PROGMEM = {0xb5, 0x4d, 0xf8, 0x13, 0x9e, 0x12, 0x4c, 0x6c, 0xe7, 0x45, 0x19, 0xe2, 0x7d, 0x5e, 0x0b, 0x01};
static uint8_t image_header[sizeof(image_header_t)];

#if (USE_NONCE == 1)
static uint8_t nonce[16];
#endif
static uint8_t boot_status = 0;
static uint8_t iv[16];

static void send_packet(uint8_t cmd, const void *payload, uint8_t len)
{
    uint8_t buf[32];
    buf[0] = STX; buf[1] = cmd; buf[2] = len;
    if (len) memcpy(&buf[3], payload, len);
    uint16_t crc = crc16_ccitt(0xFFFF, buf, 3 + len);
    memcpy(&buf[3 + len], &crc, 2);
    uart_transmit(buf, 5 + len);
}
 
void boot_goto_app(void)
{
    shared_area.boot_key = 0;
	MCUCR = (1 << IVCE); MCUCR = 0;
	asm ( "jmp 0x0000" );
}

uint8_t boot_check_image(void)
{
    uint8_t x[16] = {0}, buffer[16], key[16];
    struct AES_ctx ctx;
    memcpy_P(image_header, (void *)IMAGE_HEADER_ADDRESS, sizeof(image_header_t));
    image_header_t *p_hdr = (image_header_t *)image_header;
    if(BOOT_MAGIC != p_hdr->magic) return 0;
    memcpy_P(key, aes_key, 16);
    AES_init_ctx(&ctx, key);
    uint32_t offset = 0;
    while (offset < p_hdr->image_size)
    {
        uint8_t len = (p_hdr->image_size - offset > 16) ? 16 : (uint8_t)(p_hdr->image_size - offset);
        memcpy_P(buffer, (const void *)(uint16_t)offset, len);
        if (len < 16) { buffer[len] = 0x80; memset(buffer + len + 1, 0, 15 - len); }
        for (uint8_t i = 0; i < 16; i++) x[i] ^= buffer[i];
        AES_ECB_encrypt(&ctx, x);
        offset += len;
    }
    memcpy_P(buffer, (const void *)(uint16_t)p_hdr->image_size, 16);
    return (memcmp(x, buffer, 16) == 0);
}

void bootloader_process(void)
{
    uint8_t rx_len, rx_buf[UART_RX_BUFFER_LEN];
    if (uart_is_packet_ready(&rx_len))
    {
        uart_read_packet(rx_buf, rx_len);
        uint8_t cmd = rx_buf[1];
        uint8_t *data = &rx_buf[3];
        if(0 == boot_status) {
            if(BOOT_CMD_INFO == cmd) {
                uint8_t key[16];
                memcpy_P(key, aes_key, 16);
                AES_init_ctx(&aes_ctx, key);
                memcpy(iv, data + 4, 16);
#if (USE_NONCE == 1)
                for(uint8_t i=0; i<16; i++) nonce[i] = (uint8_t)tick;
                send_packet(BOOT_CMD_ACK, nonce, 16);
#else
                send_packet(BOOT_CMD_ACK, NULL, 0);
#endif
                boot_status = 1;
            }
        } else {
            if(BOOT_CMD_FLASH == cmd) {
                uint32_t offset; memcpy(&offset, data + 1, 4);
                uint8_t len = data[0];
                uint8_t *b = data + 5;
                for (uint8_t i = 0; i < len; i += 16) {
                    uint8_t stream[16];
                    memcpy(stream, iv, 16);
                    AES_ECB_encrypt(&aes_ctx, stream);
                    for (uint8_t j = 0; j < 16; j++) b[i + j] ^= stream[j];
                    for (int8_t j = 15; j >= 0; j--) { if (++iv[j] != 0) break; }
                }
                uint32_t addr = (offset & 0x7FFFFFFF);
                uint8_t sreg = SREG; cli();
                boot_page_erase(addr); boot_spm_busy_wait();  
                for (uint16_t i = 0; i < SPM_PAGESIZE; i += 2) {
                    uint16_t w = *b++; w += (*b++) << 8;
                    boot_page_fill(addr + i, w);
                }
                boot_page_write(addr); boot_spm_busy_wait();
                SREG = sreg; sei();
                send_packet(BOOT_CMD_ACK, NULL, 0);
                if ((offset & 0x80000000) && boot_check_image()) boot_goto_app();
            }
            if(BOOT_CMD_RESET == cmd) { shared_area.boot_key = 0; wdt_enable(WDTO_15MS); while(1); }
        }
    } else {
        static uint32_t t;
        if((tick - t) > 250) {
            t = tick;
            send_packet(BOOT_CMD_HEADER, image_header, sizeof(image_header_t));
        }
    }
}