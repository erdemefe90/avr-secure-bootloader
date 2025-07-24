#ifndef UART_H_
#define UART_H_

#define STX                     0xAA
#define UART_TX_BUFFER_LEN      128u
#define UART_RX_BUFFER_LEN      256u
#define BAUDRATE                115200u
#define CRC_LEN                 (sizeof(uint16_t))

typedef enum
{
    UART_STATUS_TX_BUSY,
    UART_STATUS_RX_BUSY,
} uart_status_t;

typedef enum
{
    UART_RS485_READ,
    UART_RS485_WRITE,
} uart_rs485_rw_t;

typedef void (*fp_rs485)(uart_rs485_rw_t rw);
typedef volatile uint32_t (*fp_tick)(void);

void uart_init(fp_rs485 rs485_func);
int8_t uart_transmit(void * const data, const uint8_t length);
uint32_t uart_get_last_rcv_tick(void);
uint8_t uart_is_packet_ready(uint8_t * const length);
void uart_read_packet(void * const dest, const uint8_t length);
void uart_rx_timeout_check(void);

#endif /* UART_H_ */