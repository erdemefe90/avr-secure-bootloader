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

#define BOOT_CMD_HEADER		    0xb0
#define BOOT_CMD_INFO		    0xb1
#define BOOT_CMD_FLASH	        0xb3
#define BOOT_CMD_ACK		    0xb5
#define BOOT_CMD_NACK		    0xb6
#define BOOT_CMD_RESET		    0xb7

#define MAX_PAYLOAD_LEN         (UART_TX_BUFFER_LEN - (PKT_HEADER_LEN + CRC_LEN))
#define PKT_HEADER_LEN		    0x03 // STX + CMD + LEN

typedef struct
{
    uint8_t stx;
    uint8_t command;
    uint8_t payload_length;
    uint8_t data[MAX_PAYLOAD_LEN];
} packet_t;

typedef struct  
{    
    uint8_t length;
    uint32_t offset;
    uint8_t data[MAX_PAYLOAD_LEN - 5]; // 1 byte length 4 byte offset
} image_resp_t;

extern volatile shared_memory_t shared_area __attribute__((section(".shared_memory")));

extern volatile uint32_t tick;
static struct AES_ctx aes;
static uint8_t aes_key[AES_BLOCKLEN] = {0xb5, 0x4d, 0xf8, 0x13, 0x9e, 0x12, 0x4c, 0x6c, 0xe7, 0x45, 0x19, 0xe2, 0x7d, 0x5e, 0x0b, 0x01};
static uint8_t image_header[sizeof(image_header_t)];
static uint8_t ack_packet[] = {STX, BOOT_CMD_ACK, 0, 0x39, 0x57};       /* ACK and NACK packets are sent directly to avoid consuming flash size */
static uint8_t nack_packet[] = {STX, BOOT_CMD_NACK, 0, 0x6a, 0x02};
static uint8_t boot_status = 0;

static void send_packet(const uint8_t command, const void * const payload, const uint8_t payload_len)
{
    uint8_t buffer[UART_TX_BUFFER_LEN];
    buffer[0] = STX;
    buffer[1] = command;
    buffer[2] = payload_len;
    
    if (payload_len > 0 && payload != NULL)
    {
        memcpy(&buffer[PKT_HEADER_LEN], payload, payload_len);
    }

    uint16_t crc = crc16_ccitt(0xFFFF, (uint8_t *)buffer, PKT_HEADER_LEN + payload_len);
    memcpy(&buffer[PKT_HEADER_LEN + payload_len], &crc, CRC_LEN);
    uart_transmit(buffer, PKT_HEADER_LEN + payload_len + CRC_LEN);
}
 
void boot_goto_app(void)
{
    shared_area.boot_key = 0;
	/* Enable change of Interrupt Vectors */
	MCUCR = (1 << IVCE);
	/* Move interrupts to 0x0000 */
	MCUCR = 0;
	asm ( "jmp 0x0000" );
}

static uint16_t calculate_flash_crc(uint32_t image_start, uint32_t image_size)
{
    uint16_t crc = 0xFFFF;
    uint16_t offset = 0;
    uint8_t buffer[32];

    while (offset < image_size)
    {
        uint8_t len = (image_size - offset > sizeof(buffer)) ? sizeof(buffer) : (image_size - offset);
        for (uint8_t i = 0; i < len; i++)
        {
            buffer[i] = pgm_read_byte_near(image_start + offset + i);
        }

        crc = crc16_ccitt(crc, buffer, len);
        offset += len;
    }

    return crc;
}

uint8_t boot_check_image(void)
{
	uint8_t ret = 0;

    memcpy_P(image_header, (void *)IMAGE_HEADER_ADDRESS, sizeof(image_header_t));
    uint32_t  * image_size = ((uint32_t *)&image_header[16]);
    uint32_t * magic = ((uint32_t *)&image_header[0]);
    uint16_t flash_crc;

    memcpy_P(&flash_crc, (const void *)*image_size, sizeof(uint16_t));

	if(BOOT_MAGIC == *magic)
	{
        uint16_t calc_crc = calculate_flash_crc(0, *image_size);
        if(flash_crc == calc_crc)
        {
            ret = 1;
        }
	}
	return ret;
}

static void boot_program_page(uint32_t page, uint8_t *buf) {
    uint16_t i;
    uint8_t sreg;
    uint32_t addr = page * SPM_PAGESIZE;
    sreg = SREG;
    cli();

    boot_page_erase(addr);
    boot_spm_busy_wait();  

    for (i = 0; i < SPM_PAGESIZE; i += 2) 
    {
        uint16_t w = *buf++;
        w += (*buf++) << 8;
        
        boot_page_fill(addr + i, w);
    }

    boot_page_write(addr);
    boot_spm_busy_wait();

    SREG = sreg;
    sei();
}

static void reset()
{
    shared_area.boot_key = 0;
    wdt_enable(WDTO_15MS);
    while (1);
}

void bootloader_process(void)
{
    static uint8_t rx_length;
    static uint8_t rx_buffer[UART_RX_BUFFER_LEN];
    packet_t * p_pkt;

    if (uart_is_packet_ready(&rx_length))
    {
        uart_read_packet(rx_buffer, rx_length);
        
        p_pkt = (packet_t *)rx_buffer;
        if (rx_length < PKT_HEADER_LEN + CRC_LEN) return;
        if (p_pkt->stx != STX) return;
    }
    else
    {
        memset(rx_buffer, 0, sizeof(rx_buffer));
    }
    
    if(0 == boot_status)
    {
        static uint32_t send_time;
        if((tick - send_time) > 250)
        {
            send_time = tick;
            send_packet(BOOT_CMD_HEADER, image_header, sizeof(image_header_t));
        }
        if(BOOT_CMD_INFO == p_pkt->command)
        {
            AES_init_ctx_iv(&aes, aes_key, &p_pkt->data[4]);
            uart_transmit(ack_packet, sizeof(ack_packet));
            boot_status = 1;
        }
    }
    else if (1 == boot_status)
    {
        if(BOOT_CMD_FLASH == p_pkt->command)
        {
            image_resp_t *p_resp = (image_resp_t *)p_pkt->data;
            if (0 == (p_resp->length % AES_BLOCKLEN))
            {
                AES_CBC_decrypt_buffer(&aes, p_resp->data, p_resp->length);

                uint8_t last = (p_resp->offset & 0x80000000) ? 1 : 0;
                uint32_t offset = (p_resp->offset & 0x7FFFFFFF);

                boot_program_page(offset / SPM_PAGESIZE, p_resp->data);
    
                uart_transmit(ack_packet, sizeof(ack_packet));
                
                if (last)
                {
                    if(boot_check_image())
                    {
                        boot_goto_app();
                    }
                    else
                    {
                        reset();
                    }
                }
            }
            else
            {
                uart_transmit(nack_packet, sizeof(nack_packet));
            }
        }
        if(BOOT_CMD_RESET == p_pkt->command)
        {
            reset();
        }
    }
}