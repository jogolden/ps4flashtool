// golden

#include "nvs.h"

int nvs_read(unsigned char *flashdata, unsigned int bank, unsigned int block, unsigned int offset, int size, unsigned char *buffer) {
    if(bank != 0) {
        printf("error: invalid NVS bank number %i\n", bank);
        return 1;
    }

    if(block > 4) {
        printf("error: invalid NVS block number %i\n", block);
        return 1;
    }

    if(offset >= g_nvs_block_sizes[block]) {
        printf("error: invalid NVS offset 0x%X\n", offset);
        return 1;
    }

    memcpy(buffer, flashdata + g_nvs_block_offsets[block] + offset, size);

    return 0;
}

int nvs_write(unsigned char *flashdata, unsigned int bank, unsigned int block, unsigned int offset, int size, unsigned char *buffer) {
    if(bank != 0) {
        printf("error: invalid NVS bank number %i\n", bank);
        return 1;
    }

    if(block > 4) {
        printf("error: invalid NVS block number %i\n", block);
        return 1;
    }

    if(offset >= g_nvs_block_sizes[block]) {
        printf("error: invalid NVS offset 0x%X\n", offset);
        return 1;
    }

    memcpy(flashdata + g_nvs_block_offsets[block] + offset, buffer, size);

    return 0;
}
