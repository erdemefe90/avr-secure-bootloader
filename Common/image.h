#ifndef IMEGE_H_
#define IMAGE_H

#define IMAGE_HEADER_ADDRESS    (0x0068)

#define BOOT_COMMAND    "BOOT\n"  
#define BOOT_KEY        0xabcd
#define BOOT_MAGIC		0xefefefef

typedef struct
{
    const uint8_t major;
    const uint8_t minor;
    const uint16_t revision;
    const uint32_t build_num;
} sw_version_t;

typedef struct
{
    const uint8_t major;
    const uint8_t minor;
    const uint16_t revision;
} hw_version_t;

typedef struct
{
    const uint32_t magic;           // 4
    const sw_version_t sw_version;  // 8
    const hw_version_t hw_version;  // 4
    const uint32_t image_size;      // 4
    const char compile_date[12];    // 12
    const char compile_time[9];     // 9
    const char avr_gcc_version[6];  // 6
    uint8_t reserved[39];
    uint16_t crc;                   // 2
} image_header_t;                   // 88

typedef struct
{
    uint32_t boot_key;
    uint32_t baud_rate;
} shared_memory_t;

#endif