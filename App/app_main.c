#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>
#include "image.h"
#include "circular_buffer.h"
#include "uart.h"
#include "timer.h"

#define SW_VERSION_MAJOR       1
#define SW_VERSION_MINOR       0
#define SW_VERSION_REVISION    2
#define SW_VERSION_BUILD       123
#define IMAGE_MAGIC            0xefefefefu
#define IMAGE_HW_ID            0x0301u
#define BOOT_COMMAND           "BOOT\n"

CIRCULAR_BUFFER_DEFINE (uart_tx_buf, uint8_t, 64);
CIRCULAR_BUFFER_DEFINE (uart_rx_buf, uint8_t, 64);

volatile shared_area_t shared_area __attribute__((section(".shared_memory")));
const image_header_t header __attribute__((used, section(".image_header"))) =
{
    .magic = IMAGE_MAGIC,
    .hw_id = IMAGE_HW_ID,
    .sw_major = SW_VERSION_MAJOR,
    .sw_minor = SW_VERSION_MINOR,
    .sw_revision = SW_VERSION_REVISION,
    .build_num = SW_VERSION_BUILD,
    .compile_date = __DATE__,
    .compile_time = __TIME__,
    .avr_gcc_version = __VERSION__,
};


void rs485_enable(uart_rs485_rw_t rw)
{
    if (rw == UART_RS485_WRITE) PORTD |= (1 << PD2);
    else PORTD &= ~(1 << PD2);
}

uint32_t uart_get_tick(void)
{
    return TIMER_COUNTER;
}

static uart_t uart = 
{
    .cfg = 
        {
            .uart = (uart_regs_t *)&UCSR0A,
            .tx_mode = UART_TRX_INT,
            .rx_mode = UART_TRX_INT,
            .rs485_cb = rs485_enable,
            .get_tick = uart_get_tick,
        },
    .data = 
        {
            .rx_buffer = &uart_rx_buf,
            .tx_buffer = &uart_tx_buf,
        }
};

ISR(USART_TX_vect)
{
    uart_tx_cpt_isr(&uart);
}

ISR(USART_UDRE_vect)
{
    uart_tx_isr(&uart);
}

ISR(USART_RX_vect)
{
    uart_rx_isr(&uart);
}

int main(void)
{
    DDRD |= (1 << PD2) | (1 << PD1);
    DDRD &= ~(1 << PD0);
    PORTD &= ~(1 << PD2);

    timer0_init();

    shared_area.boot_key = 0;
    uart_init(&uart, 115200);
    
    sei();
    while (1) 
    {
        wdt_reset();
        uint16_t receive_bytes = uart_get_available_bytes(&uart);
        if(receive_bytes >= sizeof(BOOT_COMMAND) - 1)
        {
            uint32_t last_char_time = uart_get_last_rcv_tick(&uart);
            if(TIMER_CHECK_COUNTER(last_char_time, MSEC(100)))
            {
                uint8_t rx_buffer[sizeof(BOOT_COMMAND) - 1];
                uart_read_byte(&uart, rx_buffer, sizeof(rx_buffer));
                if (0 == memcmp(BOOT_COMMAND, rx_buffer, sizeof(rx_buffer)))
                {
                    shared_area.boot_key = BOOT_KEY;
                    cli();
                    wdt_enable(WDTO_15MS);
                    while (1);
                }
            }
        }

        static uint32_t hello_time = 0;
        if(TIMER_CHECK_COUNTER(hello_time, MSEC(250)))
        {
            char msg[] = "Hello World!!\r\n";
            uart_transmit(&uart, msg, sizeof(msg) - 1);
            hello_time = TIMER_COUNTER;
        }
    }
}
