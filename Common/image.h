#ifndef IMAGE_H_
#define IMAGE_H_

#include <stdint.h>
#define BOOT_KEY            0xabcdu

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t hw_id;
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t sw_revision;
    uint16_t build_num;
    uint16_t image_size;
    char compile_date[12];
    char compile_time[9];
    char avr_gcc_version[6];
    uint8_t nonce[12];
    uint8_t tag[16];
} image_header_t;

typedef struct __attribute__((packed)) {
    uint16_t boot_key;
} shared_area_t;

#endif
