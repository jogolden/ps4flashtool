// golden

#ifndef _SOUTHBRIDGE_H
#define _SOUTHBRIDGE_H

#include "flashtool.h"

// emc bootrom spits the string '0x86000003' on uart when there is an error with the flash?

// These are all reversed from the EMC bootrom. I need to clean it up and rename stuff.
struct flashheader0 {
    char branding[32]; // 0x00-0x20
    unsigned int unknown0; // 0x20-0x24
    unsigned int secondHeaderBlockNum1; // 0x24-0x28
    unsigned int secondHeaderBlockNum2; // 0x28-0x2C
    unsigned int unknown1; // 0x2C-0x30
    unsigned int unknown2; // 0x30-0x34
    unsigned int headerInfoBlockNum; // 0x34-0x38
    unsigned int unknown3; // 0x38-0x3C
    unsigned int unknown4; // 0x3C-0x40
} __attribute__((packed));

struct flashheader1 {
    char branding[32]; // 0x00-0x20
    unsigned int unknown1; // 0x20-0x24
    unsigned int maxBlockNumber; // 0x24-0x28
    unsigned int unknown2; // 0x28-0x2C
    unsigned int unknown3; // 0x2C-0x30
    unsigned int dataBlockNumber; // 0x30-0x34
    unsigned int dataBlockLength; // 0x34-0x38
    unsigned int unknown4; // 0x38-0x3C
    unsigned int unknown5; // 0x3C-0x40
} __attribute__((packed));

// bootloader header
#define BLDR_MAGIC 0xD48FF9AA
#define BLDR_TYPE_EMC 0x48
#define BLDR_TYPE_EAP 0x68
struct bldr_hdr {
    unsigned int magic; // 0x00-0x04
    unsigned char unknown1; // 0x05
    unsigned char unknown2; // 0x06
    unsigned char unknown3; // 0x07
    unsigned char type; // 0x08 /* 0x48: EMC | 0x68: EAP */
    unsigned int hdr_len; // 0x08-0x0C
    unsigned int body_len; // 0x0C-0x10
    unsigned int load_addr_0; // 0x10-0x14
    unsigned int load_addr_1; // 0x14-0x18
    unsigned char fill_pattern[0x10]; // 0x18-0x28
    unsigned char key_seed[8]; // 0x28-0x30
    struct {
        unsigned char iplbodyaeskey[0x10]; // 0x30-0x40
        unsigned char iplbodyhmackey[0x10]; // 0x40-0x50
        unsigned char iplbodyhmac[0x14]; // 0x50-0x64
        unsigned char filler[8]; // 0x64-0x6C
        unsigned char headerhmac[0x14]; // 0x6C-0x80
    } crypteddata; // 0x30-0x80
    unsigned char bodystart; // 0x80 onwards
} __attribute__((packed));

#define EAP_KERNEL_STORAGE_HEADER_MAGIC 0x12EBC95C
struct eap_kernel_storage_hdr {
    unsigned int magic; // 0x00-0x04
    unsigned int unknown; /// 0x04-0x08 (version?)
    unsigned char iv[0x10]; // 0x08-0x18
    unsigned char hmacsha1[0x14]; // 0x18-0x2C
} __attribute__((packed));

#define EAP_KERNEL_HEADER_MAGIC 0x4B726E00
struct eap_kernel_hdr {
    unsigned int magic;
    unsigned int length;
} __attribute__((packed));

struct bldr_hdr *flash_locate_emc_ipl(unsigned char *flashdata, int forcehdr);
struct bldr_hdr *flash_locate_eap_kbl(unsigned char *flashdata);

int verify_emc_ipl(unsigned char *flashdata);
int decrypt_emc_ipl(unsigned char *flashdata, unsigned char **data, unsigned int *length);
int replace_emc_ipl(unsigned char *flashdata, unsigned char *newipl, int length);

int verify_eap_kbl(unsigned char *flashdata);
int decrypt_eap_kbl(unsigned char *flashdata, unsigned char **data, unsigned int *length);
int replace_eap_kbl(unsigned char *flashdata, unsigned char *newkbl, int length);

int decrypt_decompress_eap_kernel(unsigned char *eapkernel, unsigned int eaplength, unsigned char **data, unsigned int *length);

#endif /* _SOUTHBRIDGE_H */
