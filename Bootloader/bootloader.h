#ifndef BOOTLOADER_H_
#define BOOTLOADER_H_

void boot_goto_app(void);
uint8_t boot_check_image(void);
void bootloader_process(void);

#endif /* BOOTLOADER_H_ */