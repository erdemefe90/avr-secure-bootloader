#ifndef IMAGE_H_
#define IMAGE_H_

#include <stdint.h>
#define BOOT_KEY            0xabcdu

/* Flash byte addresses: read with pgm_read_* / memcpy_P, not SRAM pointers. */
#define BOOT_INFO_ADDRESS       0x7f60u
#define BOOT_INFO_SIZE          26u
#define SERIAL_NUMBER_ADDRESS  0x7ff0u
/* C string: at most 15 UTF-8 bytes + NUL. Erased/unprovisioned flash is all 0xff. */
#define SERIAL_NUMBER_SIZE     16u

typedef struct __attribute__((packed)) {
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t sw_revision;
    uint16_t build_num;
    char compile_date[12];
    char compile_time[9];
} boot_info_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t hw_id;
    uint8_t sw_major;
    uint8_t sw_minor;
    uint8_t sw_revision;
    uint16_t build_num;
    char compile_date[12];
    char compile_time[9];
    char avr_gcc_version[6];
    uint16_t image_size;
    uint8_t nonce[12];
    uint8_t tag[16];
} image_header_t;

typedef struct __attribute__((packed)) {
    uint16_t boot_key;
} shared_area_t;

#endif
