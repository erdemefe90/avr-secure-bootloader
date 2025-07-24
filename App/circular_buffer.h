#ifndef CIRCULAR_BUFFER_GUARD_H
#define CIRCULAR_BUFFER_GUARD_H

#define CIRCULAR_SUCCESS        0
#define CIRCULAR_BUFFER_FULL    -1
#define CIRCULAR_BUFFER_EMPTY   -2

#define CIRCULAR_BUFFER_DEFINE(name, type, size)    \
volatile type name##_data_space[size];     		    \
volatile circular_buffer_t name = {            	    \
    .buffer = name##_data_space,      			    \
    .head = 0,                      			    \
    .tail = 0,                      			    \
    .maxlen = size,                    			    \
    .element_size = sizeof(type)				    \
}

typedef struct
{
    volatile void * const buffer;
    int head;
    int tail;
    const int maxlen;
    uint16_t element_size;
} circular_buffer_t;

int circular_buffer_push(volatile circular_buffer_t *c, void * data);
int circular_buffer_pop(volatile circular_buffer_t *c, void * data);
int circular_buffer_push_fast(volatile circular_buffer_t *c, void ** data);
void circular_buffer_purge(volatile circular_buffer_t *c);
int circular_buffer_get_data_count(volatile circular_buffer_t *c);

#endif