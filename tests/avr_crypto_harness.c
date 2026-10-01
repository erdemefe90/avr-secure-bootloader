/* Run actual bootloader AES/CMAC code in QEMU for Python/C format agreement. */
#define main firmware_main
#include "../Bootloader/bootloader.c"
#undef main

int main(void)
{
    uint8_t tag[16];
    uint8_t page[IMAGE_PAGE_SIZE] = {0};
    init_crypto();
    mac_start();
    mac_add('I');
    mac_bytes((const uint8_t *)"abcd", 4);
    mac_finish(tag);
    UCSR0A = (1 << U2X0);
    UBRR0 = 16;
    UCSR0B = (1 << TXEN0);
    for (uint8_t i = 0; i < 16; ++i) uart_put(tag[i]);

    memcpy(target.nonce, "0123456789ab", 12);
    mac_start();
    mac_add('P');
    mac_bytes((const uint8_t *)&target, IMAGE_HEADER_SIZE);
    mac_add(0);
    mac_add(0);
    mac_bytes(page, IMAGE_PAGE_SIZE);
    mac_finish(tag);
    for (uint8_t i = 0; i < 16; ++i) uart_put(tag[i]);

    decrypt_page(0, page);
    for (uint8_t i = 0; i < 16; ++i) uart_put(page[i]);
    for (;;) { }
}
