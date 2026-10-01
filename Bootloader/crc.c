#include <stdint.h>
#include "crc.h"

uint16_t crc16_ccitt(uint16_t initial_crc, const uint8_t * data, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++)
    {
        initial_crc ^= ((uint16_t)data[i]) << 8;
        for (uint8_t j = 0; j < 8; j++)
        {
            if (initial_crc & 0x8000)
            initial_crc = (initial_crc << 1) ^ 0x1021;
            else
            initial_crc <<= 1;
        }
    }
    return initial_crc;
}