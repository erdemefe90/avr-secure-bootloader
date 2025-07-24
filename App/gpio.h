#ifndef GPIO_H_
#define GPIO_H_

typedef enum
{
    GPIO_INPUT,
    GPIO_OUTPUT,
} gpio_direction_t;

typedef enum
{
    GPIO_LOW,
    GPIO_HIGH,
    GPIO_TOGGLE,
} gpio_level_t;

typedef enum
{
    GPIO_PUPD_NO,
    GPIO_PULL_UP,
} gpio_pupd_t;
    
typedef struct
{
    void * reg;
    uint8_t pin;
} gpio_t;

void gpio_set_direction_st(void * gpio, gpio_direction_t dir);
void gpio_set_st(void * gpio, gpio_level_t level);
void gpio_pull_st(void * gpio, gpio_pupd_t pupd);
uint8_t gpio_read_st(void * gpio);
#endif