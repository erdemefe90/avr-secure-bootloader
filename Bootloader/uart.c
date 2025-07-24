#include <avr/io.h>
#include <util/atomic.h>
#include <string.h>
#include "crc.h"
#include "uart.h"

#define UART_BAUD_TO_REG(baudRate, x2)  (((F_CPU) / ((x2) ? 8UL : 16UL) / (baudRate)) - 1UL)

typedef enum {
    STATE_WAIT_STX,
    STATE_WAIT_CMD,
    STATE_WAIT_LEN,
    STATE_WAIT_DATA,
    STATE_WAIT_CRC_L,
    STATE_WAIT_CRC_H,
} rx_state_t;

static fp_rs485 rs485_cb = NULL;

extern volatile uint32_t tick;

static volatile rx_state_t rx_state = STATE_WAIT_STX;
static volatile uint8_t tx_buffer[UART_TX_BUFFER_LEN];
static volatile uint8_t rx_buffer[UART_RX_BUFFER_LEN];
static volatile uint8_t tx_count;
static volatile uint8_t tx_pos;
static volatile uint8_t rx_pos;
static volatile uint8_t status;
static volatile uint8_t packet_ready;
static volatile uint32_t last_char_tick;


static inline void rs485(uart_rs485_rw_t mode)
{
    if(rs485_cb)
    {
        rs485_cb(mode);
    }
}

static inline void parse(uint8_t byte)
{
    uint16_t * crc_received;
    uint16_t crc_calc;
    static uint8_t expected_length;
    

    switch (rx_state) 
    {
        case STATE_WAIT_STX:
        if (byte == STX) {
            status |= (1 << UART_STATUS_RX_BUSY);
            rx_pos = 0;
            rx_buffer[rx_pos++] = byte;
            rx_state = STATE_WAIT_CMD;
        }
        break;

        case STATE_WAIT_CMD:
        rx_buffer[rx_pos++] = byte;
        rx_state = STATE_WAIT_LEN;
        break;

        case STATE_WAIT_LEN:
        rx_buffer[rx_pos++] = byte;
        expected_length = byte;
        if (expected_length > (UART_RX_BUFFER_LEN - 5))
        {
            rx_state = STATE_WAIT_STX;
        }
        else if(0 == byte)
        {
            rx_state = STATE_WAIT_CRC_L;
        }
        else
        {
            rx_state = STATE_WAIT_DATA;
        }
        break;

        case STATE_WAIT_DATA:
        rx_buffer[rx_pos++] = byte;
        if (rx_pos == (3 + expected_length))
        {
            rx_state = STATE_WAIT_CRC_L;
        }
        break;

        case STATE_WAIT_CRC_L:
        rx_buffer[rx_pos++] = byte;
        rx_state = STATE_WAIT_CRC_H;
        break;

        case STATE_WAIT_CRC_H:
        rx_buffer[rx_pos++] = byte;
        crc_calc = crc16_ccitt(0xFFFF, (uint8_t *)&rx_buffer[0], (rx_pos - CRC_LEN)); // STX+CMD+LEN+DATA
        crc_received = ((uint16_t *)&rx_buffer[rx_pos - CRC_LEN]);
        if (crc_calc == *crc_received)
        {
            packet_ready = 1;
        }
        status &= ~(1 << UART_STATUS_RX_BUSY);
        rx_state = STATE_WAIT_STX;
        break;

        default:
        rx_state = STATE_WAIT_STX;
        break;
    }

}

ISR(USART_TX_vect)
{
    UCSR0B &= ~(1 << TXCIE0);
    rs485(UART_RS485_READ);
    status &= ~(1 << UART_STATUS_TX_BUSY);
}

ISR(USART_UDRE_vect)
{
    if (tx_pos < tx_count)
    {
        UDR0 = tx_buffer[tx_pos++];
    }
    else
    {
        UCSR0B &= ~(1 << UDRIE0);
        if(NULL != rs485_cb)
        {
            UCSR0A |= (1 << TXC0);
            UCSR0B |= (1 << TXCIE0);
        }
    }
}

ISR(USART_RX_vect)
{
    const uint8_t status = UCSR0A;
    const char c = UDR0;

    if (packet_ready) return;
    
    if ((status & ( (1 << FE0)| (1 << DOR0) | (1 << UPE0))) == 0)
    {
        last_char_tick = tick;
        parse(c);
    }
}

void uart_init(fp_rs485 rs485_func)
{
    rs485_cb = rs485_func;
    rs485(UART_RS485_READ);
    UCSR0A = (1 << U2X0);
    UBRR0 = UART_BAUD_TO_REG(BAUDRATE, 1);
    UCSR0B |= (1 << TXEN0) | (1 << RXEN0) | (1 << RXCIE0);
}

int8_t uart_transmit(void * const data, const uint8_t length)
{
    if ((length > UART_TX_BUFFER_LEN) || (NULL == data)) return -1;
    while (status & (1 << UART_STATUS_TX_BUSY));
    uint8_t * ptr = data;
    status |= (1 << UART_STATUS_TX_BUSY);
    rs485(UART_RS485_WRITE);
    ATOMIC_BLOCK(ATOMIC_RESTORESTATE)
    {
        for (uint8_t i = 0; i < length; i++)
        {
            tx_buffer[i] = *ptr++;
        }
        tx_count = length;
        tx_pos = 0;
    }
    UCSR0B |= (1 << UDRIE0);
    return 0;
}

uint32_t uart_get_last_rcv_tick(void)
{
    return last_char_tick;
}

uint8_t uart_is_packet_ready(uint8_t * const length)
{
    uint8_t ready;
    ATOMIC_BLOCK(ATOMIC_RESTORESTATE)
    {
        ready = packet_ready;
        if ((NULL != length) && ready)
        {
            *length = rx_pos;
        }
    }
    return ready;
}

void uart_read_packet(void * const dest, const uint8_t length)
{
    memcpy((void *)dest, (void *)rx_buffer, length);
    packet_ready = 0;
}

void uart_rx_timeout_check(void)
{
    if (rx_state != STATE_WAIT_STX)
    {
        if ((tick - last_char_tick) > 100)
        {
            rx_state = STATE_WAIT_STX;
            status &= ~(1 << UART_STATUS_RX_BUSY);
        }
    }
}