#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "circular_buffer.h"

/**
 * @brief This function pushes given data to a circular buffer
 * 
 * @param c Pointer to the circular buffer structure
 * @param data Data to be pushed to the circular buffer
 * @return int CIRCULAR_SUCCESS if successful, CIRCULAR_BUFFER_FULL if buffer is full
 */
int circular_buffer_push(volatile circular_buffer_t *c, void * data)
{
    int ret = CIRCULAR_SUCCESS;
    int next;

    next = c->head + 1; // next is where head will point to after this write.
    if (next >= c->maxlen)
    {
        next = 0;
    }

    if (next == c->tail) // if the head + 1 == tail, circular buffer is full
    {
        ret = CIRCULAR_BUFFER_FULL;
    }
    else
    {
        memcpy((uint8_t *)c->buffer + (c->head * c->element_size), data, c->element_size); // Load data and then move
        c->head = next; // head to next data offset.
    }

    return ret; // return success to indicate successful push.
}

/**
 * @brief This function pops the data from the circular buffer to given pointer address
 * 
 * @param c Pointer to the circular buffer structure
 * @param data Data where the data from the circular buffer pop 
 * @return int CIRCULAR_SUCCESS if successful, CIRCULAR_BUFFER_EMPTY if there is no data 
 */
int circular_buffer_pop(volatile circular_buffer_t *c, void * data)
{
    int ret = CIRCULAR_SUCCESS;
    int next;

    if (c->head == c->tail) // if the head == tail, we don't have any data
    {
        ret = CIRCULAR_BUFFER_EMPTY;
    }
    else
    {
        next = c->tail + 1; // next is where tail will point to after this read.
        if(next >= c->maxlen)
        {
            next = 0;
        }

        memcpy(data, (uint8_t *)c->buffer + (c->tail * c->element_size), c->element_size); // Read data and then move
        c->tail = next; // tail to next offset.
    }
    return ret; 
}

/**
 * @brief This function returns address where next data will be written in next push operation
 * 
 * @param c Pointer to the circular buffer structure
 * @param data Pointer to the address where next push operation will write to 
 * @return int CIRCULAR_SUCCESS if successful, CIRCULAR_BUFFER_FULL if buffer is full
 */
int circular_buffer_push_fast(volatile circular_buffer_t *c, void ** data)
{
    int ret = CIRCULAR_SUCCESS;
    int next;

    next = c->head + 1; // next is where head will point to after this write.
    if (next >= c->maxlen)
    {
        next = 0;
    }

    if (next == c->tail) // if the head + 1 == tail, circular buffer is full
    {
        ret = CIRCULAR_BUFFER_FULL;
    }
    else
    {
        *data = (uint8_t *)c->buffer + (c->head * c->element_size);
        c->head = next; // head to next data offset.
    }
    return ret;
}

/**
 * @brief This function drops all the data in the buffer
 * 
 * @param c Pointer to the circular buffer structure
 */
void circular_buffer_purge(volatile circular_buffer_t *c)
{
    c->tail = 0;
    c->head = 0;
}

/**
 * @brief This function returns current data count in the buffer
 * 
 * @param c Pointer to the circular buffer structure
 * @return int Total data count in the buffer
 */
int circular_buffer_get_data_count(volatile circular_buffer_t *c)
{
    int data_count = -1;

    if (c->head == c->tail)
    {
        /* Checking if buffer is empty */
        data_count = 0;
    }
    else
    {
        int next;
        next = c->head + 1; // next is where head will point to after this write. 
        if(next >= c->maxlen)
        {
            next = 0;
        }

        if (next == c->tail)
        {
            /* Checking if buffer is full */
            data_count = c->maxlen;
        }
        else
        {       
            if(c->head >= c->tail)
            {
                data_count = (c->head - c->tail);
            }
            else
            {
                data_count = (c->maxlen + c->head - c->tail);
            }
        }
    }
    
    return data_count;
}