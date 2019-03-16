// golden

#ifndef _NVS_H
#define _NVS_H

#include "flashtool.h"

// bank 0 and 1
// bank 1 is the backup bank

// bank 0 block offsets
#define FLASH_BANK0_BLOCK0_OFFSET 0x1C4000
#define FLASH_BANK0_BLOCK1_OFFSET 0x1C7000
#define FLASH_BANK0_BLOCK2_OFFSET 0x1C8000
#define FLASH_BANK0_BLOCK3_OFFSET 0x1C8800
#define FLASH_BANK0_BLOCK4_OFFSET 0x1C9000
static unsigned int g_nvs_block_offsets[5] = { 0x1C4000, 0x1C7000, 0x1C8000, 0x1C8800, 0x1C9000 };

// bank 0 block sizes
#define FLASH_BANK0_BLOCK0_SIZE 0x3000
#define FLASH_BANK0_BLOCK1_SIZE 0x1000
#define FLASH_BANK0_BLOCK2_SIZE 0x800
#define FLASH_BANK0_BLOCK3_SIZE 0x800
#define FLASH_BANK0_BLOCK4_SIZE 0x3000
static unsigned int g_nvs_block_sizes[5] = { 0x3000, 0x1000, 0x800, 0x800, 0x3000 };

// known NVS variables
#define NVS_VAR_BLOCK0_MAC_ADDRESS 0x21
#define NVS_VAR_BLOCK2_CONSOLE_INF0 0
#define NVS_VAR_BLOCK4_ENABLE_UART 0x31F

// variable structures
struct nvs_console_info {
    char moboserial[14];
    char _fill1[0x22];
    char serial[10];
    char _fill2[7];
    char model[13];
} __attribute__((packed));

int nvs_read(unsigned char *flashdata, unsigned int bank, unsigned int block, unsigned int offset, int size, unsigned char *buffer);
int nvs_write(unsigned char *flashdata, unsigned int bank, unsigned int block, unsigned int offset, int size, unsigned char *buffer);

#endif /* _NVS_H */
