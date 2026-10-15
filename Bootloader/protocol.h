#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <avr/boot.h>
#include "image.h"

#define STX                 0xaau
#define CMD_HEADER          0xb0u
#define CMD_BEGIN           0xb1u
#define CMD_PAGE            0xb3u
#define CMD_FINISH          0xb4u
#define CMD_ACK             0xb5u
#define CMD_NACK            0xb6u
#define CMD_RESET           0xb7u
#define CMD_INFO            0xb8u
#define CMD_LOCK            0xb9u
#define CMD_SERIAL          0xbau
#define SERIAL_SEQ          0xfffdu

/* CMD_LOCK programs only LB2/LB1 (1 -> 0); BLB pairs remain read-only. */
#define LOCK_APP_WRITE      0x04u
#define LOCK_APP_READ       0x08u
#define LOCK_BOOT_WRITE     0x10u
#define LOCK_PROGRAM_MASK   0x03u
#define CONTROL_SEQ         0xfffeu
typedef struct __attribute__((packed)) {
    boot_info_t boot;
    uint8_t serial[SERIAL_NUMBER_SIZE];
    uint8_t low_fuse;
    uint8_t high_fuse;
    uint8_t extended_fuse;
    uint8_t lock_bits;
} info_payload_t;

#define INFO_PAYLOAD_SIZE   sizeof(info_payload_t)

#define PAGE_TAG_SIZE       sizeof(((image_header_t *)0)->tag)
#define PAGE_PAYLOAD_SIZE   (sizeof(uint16_t) + SPM_PAGESIZE + PAGE_TAG_SIZE)
#define MAX_PAYLOAD_SIZE    PAGE_PAYLOAD_SIZE

#define NACK_PACKET         1u
#define NACK_STATE          2u
#define NACK_SIZE           3u
#define NACK_AUTH           4u
#define NACK_IMAGE          5u
#define NACK_LOCK           6u

#endif
