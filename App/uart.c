#include <stdlib.h>
#include <avr/interrupt.h>
#include <util/atomic.h>
#include "circular_buffer.h"
#include "uart.h"

#define UART_BAUD_TO_REG(baudRate, x2)  (((F_CPU) / ((x2) ? 8UL : 16UL) / (baudRate)) - 1UL)
#define UART_REG_TO_BAUD(regValue, x2)  ((F_CPU) / ((x2) ? 8UL : 16UL) / ((regValue) + 1UL))
#define BAUD_ERROR(target, actual) (10000UL * abs((int32_t)(target) - (int32_t)(actual)) / (target))

#define _RXC    7
#define _TXC    6
#define _UDRE   5
#define _FE     4
#define _DOR    3
#define _UPE    2
#define _U2X    1
#define _MPCM   0

#define _RXCIE  7
#define _TXCIE  6
#define _UDRIE  5
#define _RXEN   4
#define _TXEN   3

#define _U2X0   1

static inline void rs485(uart_t * const p_uart, uart_rs485_rw_t mode)
{
    if(NULL != p_uart->cfg.rs485_cb)
    {
        p_uart->cfg.rs485_cb(mode);
    }
}

void uart_init(uart_t * const p_uart, const uint32_t baud_rate)
{
    uart_regs_t * const p_reg = p_uart->cfg.uart;
    circular_buffer_purge(p_uart->data.rx_buffer);
    circular_buffer_purge(p_uart->data.tx_buffer);
    p_uart->data.status = 0;
    rs485(p_uart, UART_RS485_READ);

    p_reg->UCSR_A = 0;

    uint16_t reg_normal = UART_BAUD_TO_REG(baud_rate, 0);
    uint16_t reg_double = UART_BAUD_TO_REG(baud_rate, 1);
    uint32_t err_normal = BAUD_ERROR(baud_rate, UART_REG_TO_BAUD(reg_normal, 0));
    uint32_t err_double = BAUD_ERROR(baud_rate, UART_REG_TO_BAUD(reg_double, 1));

    if (err_double < err_normal)
    {
        p_reg->UBBR16 = reg_double;
        p_reg->UCSR_A |= (1 << _U2X0);
    }
    else
    {
        p_reg->UBBR16 = reg_normal;
    }

    uint8_t status_b = 0;
    if (p_uart->cfg.tx_mode != UART_TRX_OFF) status_b |= (1 << _TXEN);
    if (p_uart->cfg.rx_mode != UART_TRX_OFF) status_b |= (1 << _RXEN);
    if (p_uart->cfg.rx_mode == UART_TRX_INT) status_b |= (1 << _RXCIE);

    p_reg->UCSR_B = status_b;
}

void uart_tx_cpt_isr(uart_t * const p_uart)
{
    p_uart->cfg.uart->UCSR_B &= ~(1 << _TXCIE);
    rs485(p_uart, UART_RS485_READ);
    p_uart->data.status &= ~(1 << UART_STATUS_TX_BUSY);
}

void uart_tx_isr(uart_t * const p_uart)
{
    uint16_t data_count = circular_buffer_get_data_count(p_uart->data.tx_buffer);
    if(data_count)
    {
        uint8_t c;
        circular_buffer_pop(p_uart->data.tx_buffer, &c);
        if (p_uart->cfg.uart->UCSR_A & (1 << _UDRE))
        {
            p_uart->cfg.uart->U_DR = c;
        }
    }
    else
    {
        p_uart->cfg.uart->UCSR_B &= ~(1 << _UDRIE);
        p_uart->cfg.uart->UCSR_A |= (1 << _TXC);
        p_uart->cfg.uart->UCSR_B |= (1 << _TXCIE);
    }
}

void uart_rx_isr(uart_t * const p_uart)
{
    const uint8_t status = p_uart->cfg.uart->UCSR_A;
    if ((status & ( (1 << _FE)| (1 << _DOR) | (1 << _UPE))) == 0)
    {
        uint8_t c = p_uart->cfg.uart->U_DR;
        circular_buffer_push(p_uart->data.rx_buffer, &c);
        if(NULL != p_uart->cfg.get_tick)
        {
            p_uart->data.last_char_time = p_uart->cfg.get_tick();
        }
    }
    else
    {
        uint8_t temp = p_uart->cfg.uart->U_DR;
        (void)temp;
    }
}

int8_t uart_transmit(uart_t * const p_uart, void * const data, const uint16_t length)
{
    int8_t ret = 0;
    uint8_t * ptr = data;
    uint16_t i;

    if (UART_TRX_OFF == p_uart->cfg.tx_mode)
    {
        ret = -1;
        return ret;
    }
    while(p_uart->data.status & (1 << UART_STATUS_TX_BUSY));
    p_uart->data.status |= (1 << UART_STATUS_TX_BUSY);

    rs485(p_uart, UART_RS485_WRITE);
    
    if(UART_TRX_POLL == p_uart->cfg.tx_mode)
    {
        for (i = 0; i < length; i++)
        {
            while(!(p_uart->cfg.uart->UCSR_A & (1 << _UDRE)));
            p_uart->cfg.uart->U_DR = *ptr++;
        }
        while (!(p_uart->cfg.uart->UCSR_A & (1 << _TXC)));
        rs485(p_uart, UART_RS485_READ);
        p_uart->cfg.uart->UCSR_A |= (1 << _TXC);
        p_uart->data.status &= ~(1 << UART_STATUS_TX_BUSY);
    }
    else if (UART_TRX_INT == p_uart->cfg.tx_mode)
    {
        ATOMIC_BLOCK(ATOMIC_RESTORESTATE)
        {        
            for (i = 0; i < length; i++)
            {
                circular_buffer_push(p_uart->data.tx_buffer, ptr++);
            }
        }
        p_uart->cfg.uart->UCSR_B |= (1 << _UDRIE);
    }
    return ret;
}

volatile uint32_t uart_get_last_rcv_tick(uart_t * const p_uart)
{
    return p_uart->data.last_char_time;
}

uint16_t uart_get_available_bytes(uart_t * const p_uart)
{
    return circular_buffer_get_data_count(p_uart->data.rx_buffer);
}

uint16_t uart_read_byte(uart_t * const p_uart, void * const c, const uint16_t length)
{
    uint16_t ret = 0;
    
    if(0 == length) return ret;

    uint16_t rx_bytes = uart_get_available_bytes(p_uart);
    if((length <= rx_bytes) && (NULL != c))
    {
        uint8_t * ptr = c;
        for(uint16_t i = 0; i < length; i++)
        {
            if(CIRCULAR_SUCCESS == circular_buffer_pop(p_uart->data.rx_buffer, ptr++))
            {
                ret++;
            }
            else
            {
                break;
            }
        }
    }
    return ret;
}