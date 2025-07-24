#ifndef UART_H_
#define UART_H_

typedef struct
{
    uint8_t UCSR_A;
    uint8_t UCSR_B;
    uint8_t UCSR_C;
    uint8_t _resvd1;
    union {
        uint16_t UBBR16;
        uint8_t  UBBR8[2];
    };
    uint8_t U_DR;
}uart_regs_t;

typedef enum
{
    UART_STATUS_TX_BUSY,
    UART_STATUS_RX_BUSY,
} uart_status_t;

typedef enum
{
    UART_TRX_OFF,
    UART_TRX_POLL,
    UART_TRX_INT,
} uart_trx_mode_t;

typedef enum
{
    UART_RS485_READ,
    UART_RS485_WRITE,
} uart_rs485_rw_t;

typedef void (*fp_rs485)(uart_rs485_rw_t rw);
typedef void (*fp_rx_callback)(uint8_t * buffer, uint16_t rx_length);
typedef volatile uint32_t (*fp_get_tick)(void);

typedef struct
{
    volatile circular_buffer_t * const rx_buffer;
    volatile circular_buffer_t * const tx_buffer;
    volatile uint8_t status;
    volatile uint32_t last_char_time;
} uart_data_t;

typedef struct
{
    uart_regs_t * uart;
    uart_trx_mode_t rx_mode;
    uart_trx_mode_t tx_mode;
    fp_rs485 rs485_cb;
    fp_rx_callback rx_cb;
    fp_get_tick get_tick;
} uart_config_t;

typedef struct
{
    uart_config_t cfg;
    uart_data_t data;
} uart_t;


void uart_init(uart_t * p_uart, const uint32_t baud_rate);
int8_t uart_transmit(uart_t * const p_uart, void * const data, const uint16_t length);
void uart_tx_cpt_isr(uart_t * const p_uart);
void uart_tx_isr(uart_t * const p_uart);
void uart_rx_isr(uart_t * const p_uart);
volatile uint32_t uart_get_last_rcv_tick(uart_t * const p_uart);
uint16_t uart_get_available_bytes(uart_t * const p_uart);
uint16_t uart_read_byte(uart_t * const p_uart, void * const c, const uint16_t length);
#endif /* UART_H_ */