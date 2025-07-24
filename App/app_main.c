#include <stdlib.h>
#include <string.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include <avr/wdt.h>
#include "gpio.h"
#include "image.h"
#include "circular_buffer.h"
#include "uart.h"
#include "timer.h"

#define SW_VERSION_MAJOR       1
#define SW_VERSION_MINOR       0
#define SW_VERSION_REVISION    2
#define SW_VERSION_BUILD       122

#define HW_VERSION_MAJOR       3
#define HW_VERSION_MINOR       1
#define HW_VERSION_REVISION    2

CIRCULAR_BUFFER_DEFINE (uart_tx_buf, uint8_t, 64);
CIRCULAR_BUFFER_DEFINE (uart_rx_buf, uint8_t, 64);

volatile shared_memory_t shared_area __attribute__((section(".shared_memory")));
const image_header_t header __attribute__((section(".image_header")))  = 
{
    .magic = BOOT_MAGIC,
    .sw_version = 
    {
        .major = SW_VERSION_MAJOR,
        .minor = SW_VERSION_MINOR,
        .revision = SW_VERSION_REVISION,
        .build_num = SW_VERSION_BUILD,
    },
    .hw_version = 
    {
        .major = HW_VERSION_MAJOR,
        .minor = HW_VERSION_MINOR,
        .revision = HW_VERSION_REVISION,
    },
    .compile_date = __DATE__,
    .compile_time = __TIME__,
    .avr_gcc_version = __VERSION__,
};

static gpio_t led = {(gpio_t *)&PINB, 5};

static gpio_t rx_pin = {(gpio_t *)&PIND, 0};
static gpio_t tx_pin = {(gpio_t *)&PIND, 1};
static gpio_t en_pin = {(gpio_t *)&PIND, 2};


void rs485_enable(uart_rs485_rw_t rw)
{
    gpio_set_st(&en_pin, rw);
}

volatile uint32_t uart_get_tick(void)
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
    gpio_set_direction_st(&en_pin, GPIO_OUTPUT);
    gpio_set_direction_st(&led, GPIO_OUTPUT);
    gpio_set_direction_st(&tx_pin, GPIO_OUTPUT);
    gpio_set_direction_st(&rx_pin, GPIO_INPUT);

    timer0_init();

    shared_area.boot_key = 0;
    shared_area.baud_rate = 115200;
    uart_init(&uart, shared_area.baud_rate);
    
    sei();
    while (1) 
    {
        wdt_reset();
        uint16_t receive_bytes = uart_get_available_bytes(&uart);
        if(receive_bytes)
        {
            uint32_t last_char_time = uart_get_last_rcv_tick(&uart);
            if(TIMER_CHECK_COUNTER(last_char_time, MSEC(100)))
            {
                uint8_t rx_buffer[16];
                uart_read_byte(&uart, rx_buffer, receive_bytes);
                if (0 == strncmp((char *)BOOT_COMMAND, (char *)rx_buffer, receive_bytes))
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
            uart_transmit(&uart, msg, sizeof(msg));
            hello_time = TIMER_COUNTER;
        }
    }
}

