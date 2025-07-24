#include <stdint.h>
#include "gpio.h"

typedef struct
{
    uint8_t PIN;
    uint8_t DDR;
    uint8_t PORT;
} gpio_regs_t;

static void gpio_set_direction(gpio_regs_t * reg, uint8_t pin_num, gpio_direction_t dir)
{
    (GPIO_INPUT == dir) ? (reg->DDR &= ~(1 << pin_num)) : (reg->DDR |= (1 << pin_num));
}

void gpio_set_direction_st(void * gpio, gpio_direction_t dir)
{
    gpio_t * p_gpio = (gpio_t *)gpio;
    gpio_set_direction(p_gpio->reg, p_gpio->pin, dir);
}

static void gpio_set(gpio_regs_t * reg, uint8_t pin_num, gpio_level_t level)
{
    if(GPIO_LOW == level)
    {
        (reg->PORT &= ~(1 << pin_num));
    }
    else if(GPIO_HIGH == level)
    {
        (reg->PORT |= (1 << pin_num));
    }
    else if(GPIO_TOGGLE == level)
    {
        (reg->PORT ^= (1 << pin_num));
    }
}

void gpio_set_st(void * gpio, gpio_level_t level)
{
    gpio_t * p_gpio = (gpio_t *)gpio;
    gpio_set(p_gpio->reg, p_gpio->pin, level);
}

void gpio_pull_st(void * gpio, gpio_pupd_t pupd)
{
    gpio_set_st(gpio, (gpio_level_t)pupd);
}

static uint8_t gpio_read(gpio_regs_t * reg, uint8_t pin_num)
{
    return (reg->PIN & (1 << pin_num));
}

uint8_t gpio_read_st(void * gpio)
{
    gpio_t * p_gpio = (gpio_t *)gpio;
    return gpio_read(p_gpio->reg, p_gpio->pin);
}