#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include "image.h"

#define STX                 0xaau
#define CMD_HEADER          0xb0u
#define CMD_BEGIN           0xb1u
#define CMD_PAGE            0xb3u
#define CMD_FINISH          0xb4u
#define CMD_ACK             0xb5u
#define CMD_NACK            0xb6u
#define CMD_RESET           0xb7u

#define PAGE_TAG_SIZE       16u
#define PAGE_PAYLOAD_SIZE   (2u + IMAGE_PAGE_SIZE + PAGE_TAG_SIZE)
#define MAX_PAYLOAD_SIZE    PAGE_PAYLOAD_SIZE

#define NACK_PACKET         1u
#define NACK_STATE          2u
#define NACK_SIZE           3u
#define NACK_AUTH           4u
#define NACK_IMAGE          5u

#endif
