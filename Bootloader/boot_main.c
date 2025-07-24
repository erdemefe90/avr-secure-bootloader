#include <stdlib.h>
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>
#include "image.h"
#include "uart.h"
#include "bootloader.h"

/* BOOT LED Pin Definition */
#define LED_PORT PORTB
#define LED_DDR  DDRB
#define LED_PIN  5
/* RS485 TX Pin Definition */
#define TX_PORT PORTD
#define TX_DDR  DDRD
#define TX_PIN  1
/* RS485 TX Pin Definition */
#define RX_PORT PORTD
#define RX_DDR  DDRD
#define RX_PIN  0
/* RS485 EN Pin Definition */
#define EN_PORT PORTD
#define EN_DDR  DDRD
#define EN_PIN  2

/* This RAM section is defined in Bootloader_Custom.ld. It is used share data between Bootloader and App */
volatile shared_memory_t shared_area __attribute__((section(".shared_memory")));
volatile uint32_t tick;

void rs485_enable(uart_rs485_rw_t rw)
{
    rw ? (EN_PORT |= (1 << EN_PIN)) : (EN_PORT &= ~(1 << EN_PIN));
}

ISR(TIMER0_COMPA_vect)
{
    tick++;
}

int main(void)
{
    cli();
    /* Enable change of Interrupt Vectors */
    MCUCR = (1 << IVCE);
    /* Move interrupts to Boot Flash section */
    MCUCR = (1 << IVSEL);

    wdt_enable(WDTO_8S); 

    LED_DDR |= (1 << LED_PIN);
    TX_DDR |= (1 << TX_PIN);
    EN_DDR |= (1 << EN_PIN);
    RX_DDR &= ~(1 << RX_PIN);

    TCCR0A = 0x02;  //  CTC Mode
    TCCR0B = 0x03;  //  16000000/64 = 250kHz
    OCR0A = 249;    //  1ms
    TIMSK0 |= 0x02;
	
    uart_init(rs485_enable);
    sei();

    if((boot_check_image() != 0) && (shared_area.boot_key != BOOT_KEY))
    {
        boot_goto_app();
    }

    while (1) 
    {
        wdt_reset();
		bootloader_process();
		uart_rx_timeout_check();
		static uint32_t blink_time = 0;
		if((tick - blink_time) >= 500)
		{
    		blink_time = tick;
    		LED_PORT ^= (1 << LED_PIN);
		}
    }
}

