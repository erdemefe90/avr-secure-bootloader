#ifndef TIMER_H_
#define TIMER_H_

volatile uint32_t get_tick(void);
void timer0_init(void);

#define TIMER_COUNTER                              get_tick()

#define TIMER_TICKS_PER_MILLISECOND                (1U)
#define TIMER_TICKS_PER_SECOND                     (1000U * TIMER_TICKS_PER_MILLISECOND)
#define TIMER_TICK_PER_MINUTE                      (60U * TIMER_TICKS_PER_SECOND)
#define TIMER_CHECK_COUNTER(variable, interval)    (((TIMER_COUNTER - variable) > interval))

#define MSEC(x)             (x * TIMER_TICKS_PER_MILLISECOND)
#define SEC(x)              (x * TIMER_TICKS_PER_SECOND)
#define MINUTE(x)           (x * TIMER_TICK_PER_MINUTE)

#endif