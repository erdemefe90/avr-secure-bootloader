#include <avr/io.h>
#include <avr/interrupt.h>
#include <util/atomic.h>
#include <stdint.h>
#include "timer.h"

static volatile uint32_t tick = 0;

uint32_t get_tick(void)
{
    uint32_t value;
    ATOMIC_BLOCK(ATOMIC_RESTORESTATE) { value = tick; }
    return value;
}

ISR(TIMER0_COMPA_vect)
{
    tick++;
}


void timer0_init (void)
{
    TCCR0A = 0x02;  //  CTC Mode
    TCCR0B = 0x03;  //  16000000/64 = 250kHz
    OCR0A = 249;    //  1ms
    TIMSK0 |= 0x02;
}
