#ifndef CRC_H
#define CRC_H

uint16_t crc16_ccitt(uint16_t initial_crc, const uint8_t * data, uint16_t len);

#endif