// golden

#include "southbridge.h"

/*
https://www.kernel.org/doc/readme/Documentation-arm-Marvell-README
https://www.kernel.org/doc/Documentation/devicetree/bindings/arm/syna.txt
https://www.kernel.org/doc/Documentation/devicetree/bindings/arm/marvell/
  Sheeva PJ4 88sv581x "Flareon"
    CPUID 0x560f581x
    ARMv7, idivt, optional iWMMXt v2
  Sheeva PJ4B 88sv581x
    CPUID 0x561f581x
    ARMv7, idivt, optional iWMMXt v2
  Sheeva PJ4B-MP / PJ4C
    CPUID 0x562f584x
    ARMv7, idivt/idiva, LPAE, optional iWMMXt v2 and/or NEON
*/

struct bldr_hdr *flash_locate_emc_ipl(unsigned char *flashdata, int forcehdr) {
    // reversed from EMC bootrom
    // I want to start calling the first header the meta header and then the second header the main header.
    // I cannot tell if the two slots for booting are for updates or for testkit/devkit vs retail?
    struct flashheader0 *hdr0 = NULL;
    struct flashheader1 *hdr1 = NULL;
    struct bldr_hdr *blhdr = NULL;
    unsigned char flag;
    int blocknum;

    hdr0 = (struct flashheader0 *)flashdata;

    if(verbose) {
        printf("* flash branding '%s'\n", hdr0->branding);
    }

    blocknum = hdr0->secondHeaderBlockNum2;
    flag = *(unsigned int *)(flashdata + (hdr0->headerInfoBlockNum * 0x200));
    if(!((flag >> 7) & 1)) {
        if(verbose && !forcehdr) {
            printf("* using header block num 1\n");
        }

        blocknum = hdr0->secondHeaderBlockNum1;
    } else if(verbose && !forcehdr) {
        printf("* using header block num 2\n");
    }

    hdr1 = (struct flashheader1 *)(flashdata + (blocknum * 0x200));
    blhdr = (struct bldr_hdr *)(flashdata + ((blocknum + hdr1->dataBlockNumber) * 0x200));
    
    if(blhdr->magic != BLDR_MAGIC) {
        printf("error: invalid EMC IPL bootloader header magic!\n");
        return NULL;
    }

    if(blhdr->type != BLDR_TYPE_EMC) {
        printf("error: invalid EMC IPL bootloader header type!\n");
        return NULL;
    }

    if(forcehdr == 1) {
        return (struct bldr_hdr *)(flashdata + ((hdr0->secondHeaderBlockNum1 + hdr1->dataBlockNumber) * 0x200));
    } else if(forcehdr == 2) {
        return (struct bldr_hdr *)(flashdata + ((hdr0->secondHeaderBlockNum2 + hdr1->dataBlockNumber) * 0x200));
    }

    return blhdr;
}

struct bldr_hdr *flash_locate_eap_kbl(unsigned char *flashdata) {
    struct bldr_hdr *blhdr = NULL;
    struct slb2_header *slbhdr = (struct slb2_header *)(flashdata + 0xC4000);
    struct slb2_entry *entry = NULL;
    int i;

    if(slbhdr->magic != SLB2_MAGIC) {
        printf("error: invalid KBL SLB2 magic!\n");
        return NULL;
    }

    for(i = 0; i < slbhdr->file_count; i++) {
        entry = &slbhdr->entry_list[i];

        if(!strcmp(entry->file_name, "C0010001") || !strcmp(entry->file_name, "eap_kbl")) {
            break;
        }
    }
    
    return (struct bldr_hdr *)(flashdata + 0xC4000 + (entry->block_offset << 9));
}

int verify_emc_ipl(unsigned char *flashdata) {
    struct bldr_hdr *blhdr = flash_locate_emc_ipl(flashdata, 0);
    unsigned char *hdraeskey = keymgr_getkey("emciplaes", KEY_TYPE_AES_128);
    unsigned char *hdrhmackey = keymgr_getkey("emciplhmac", KEY_TYPE_HMAC_SHA1);

    if(verbose) {
        printf("* EMC IPL header aes key: ");
        hexdump(hdraeskey, 0x10, 0);

        printf("* EMC IPL header hmac-sha1 key: ");
        hexdump(hdrhmackey, 0x10, 0);
    }

    struct bldr_hdr dechdr;
    unsigned char *decbody = (unsigned char *)malloc(blhdr->body_len);
    char bodyhmac[0x14];
    char hdrhmac[0x14];

    // copy the header on to the stack, we dont want to modify anything
    memcpy(&dechdr, blhdr, blhdr->hdr_len);
    
    aes128_cbc_iv_zero_decrypt(hdraeskey, &blhdr->crypteddata, &dechdr.crypteddata, 0x50);

    hmac_sha1(dechdr.crypteddata.iplbodyhmackey, 0x10, &blhdr->bodystart, blhdr->body_len, bodyhmac);
    hmac_sha1(hdrhmackey, 0x10, (unsigned char *)&dechdr, 0x6C, hdrhmac);

    if(verbose) {
        printf("* flash EMC IPL body hmac-sha1: ");
        hexdump(dechdr.crypteddata.iplbodyhmac, 0x14, 0);

        printf("* calculated EMC IPL body hmac-sha1: ");
        hexdump(bodyhmac, 0x14, 0);

        printf("* flash EMC IPL header hmac-sha1: ");
        hexdump(dechdr.crypteddata.headerhmac, 0x14, 0);

        printf("* calculated EMC IPL header hmac-sha1: ");
        hexdump(hdrhmac, 0x14, 0);
    }

    // some checks that the rom will do
    unsigned char *h = (unsigned char *)&dechdr;
    int flag;

    // TODO: clean this all up and make it nice :P
    flag = *(unsigned short *)&h[6] >> 14 == 1;
    if(!flag) {
        flag = *(unsigned short *)&h[6] >> 14 == 2;
    }

    if(!flag) {
        printf("error: header flag part 1 invalid!\n");
        return 1;
    }

    flag = (*(unsigned short *)&h[6] >> 12) & 3;
    if(flag == 0) {
        flag = *(unsigned short *)&h[8] == 0x80;
    }

    if(!flag || h[12] & 0x0F) {
        printf("error: header flag part 2 invalid!\n");
        return 1;
    }

    if(dechdr.load_addr_1 < 0x100C00) {
        printf("error: invalid load address!\n");
        return 1;
    }

    // TODO: add size checks also and other stuff

    free(decbody);

    return memcmp(bodyhmac, dechdr.crypteddata.iplbodyhmac, sizeof(bodyhmac)) + 
        memcmp(hdrhmac, &dechdr.crypteddata.headerhmac, sizeof(bodyhmac));
}

int decrypt_emc_ipl(unsigned char *flashdata, unsigned char **data, unsigned int *length) {
    struct bldr_hdr *blhdr = flash_locate_emc_ipl(flashdata, 0);
    unsigned char *hdraeskey = keymgr_getkey("emciplaes", KEY_TYPE_AES_128);
    
    if(verbose) {
        printf("* EMC IPL header aes key: ");
        hexdump(hdraeskey, 0x10, 0);
    }

    struct bldr_hdr dechdr;
    unsigned char *decbody = (unsigned char *)malloc(blhdr->body_len);

    // copy the header on to the stack, we dont want to modify anything
    memcpy(&dechdr, blhdr, blhdr->hdr_len);
    aes128_cbc_iv_zero_decrypt(hdraeskey, &blhdr->crypteddata, &dechdr.crypteddata, 0x50);
    aes128_cbc_iv_zero_decrypt(dechdr.crypteddata.iplbodyaeskey, &blhdr->bodystart, decbody, blhdr->body_len);

    if(data) {
        *data = decbody;
    }

    if(length) {
        *length = blhdr->body_len;
    }

    return 0;
}

int replace_emc_ipl(unsigned char *flashdata, unsigned char *newipl, int length) {
    struct bldr_hdr *blhdr = flash_locate_emc_ipl(flashdata, 0);
    unsigned char *hdraeskey = keymgr_getkey("emciplaes", KEY_TYPE_AES_128);
    unsigned char *hdrhmackey = keymgr_getkey("emciplhmac", KEY_TYPE_HMAC_SHA1);

    if(verbose) {
        printf("* EMC IPL header aes key: ");
        hexdump(hdraeskey, 0x10, 0);

        printf("* EMC IPL header hmac-sha1 key: ");
        hexdump(hdrhmackey, 0x10, 0);
    }

    char bodyhmac[0x14];
    char hdrhmac[0x14];

    // decrypt header
    aes128_cbc_iv_zero_decrypt(hdraeskey, &blhdr->crypteddata, &blhdr->crypteddata, 0x50);

    // encrypt body and replace it in flash
    if(verbose) {
        printf("* old EMC IPL body_len 0x%X\n", blhdr->body_len);
        printf("* new EMC IPL body_len 0x%X\n", length);
    }

    if(blhdr->body_len != length) {
        printf("warning: new EMC IPL has a different body length\n");
    }

    blhdr->body_len = length;
    aes128_cbc_iv_zero_encrypt(blhdr->crypteddata.iplbodyaeskey, newipl, &blhdr->bodystart, blhdr->body_len);

    // replace body signature
    hmac_sha1(blhdr->crypteddata.iplbodyhmackey, 0x10, &blhdr->bodystart, blhdr->body_len, bodyhmac);

    if(verbose) {
        printf("* old EMC IPL body hmac-sha1: ");
        hexdump(blhdr->crypteddata.iplbodyhmac, 0x14, 0);

        printf("* new EMC IPL body hmac-sha1: ");
        hexdump(bodyhmac, 0x14, 0);
    }

    memcpy(blhdr->crypteddata.iplbodyhmac, bodyhmac, sizeof(bodyhmac));

    // filler null
    memset(blhdr->crypteddata.filler, 0, 8);

    // replace header signature
    hmac_sha1(hdrhmackey, 0x10, (unsigned char *)blhdr, 0x6C, hdrhmac);

    if(verbose) {
        printf("* old EMC IPL header hmac-sha1: ");
        hexdump(blhdr->crypteddata.headerhmac, 0x14, 0);

        printf("* new EMC IPL header hmac-sha1: ");
        hexdump(hdrhmac, 0x14, 0);
    }

    memcpy(blhdr->crypteddata.headerhmac, hdrhmac, sizeof(hdrhmac));

    // encrypt header
    aes128_cbc_iv_zero_encrypt(hdraeskey, &blhdr->crypteddata, &blhdr->crypteddata, 0x50);

    return 0;
}

int verify_eap_kbl(unsigned char *flashdata) {
    struct bldr_hdr *blhdr = flash_locate_eap_kbl(flashdata);
    unsigned char *hdraeskey = keymgr_getkey("eapkblaes", KEY_TYPE_AES_128);
    unsigned char *hdrhmackey = keymgr_getkey("eapkblhmac", KEY_TYPE_HMAC_SHA1);

    if(verbose) {
        printf("* EAP KBL header aes key: ");
        hexdump(hdraeskey, 0x10, 0);

        printf("* EAP KBL header hmac-sha1 key: ");
        hexdump(hdrhmackey, 0x10, 0);
    }

    struct bldr_hdr dechdr;
    unsigned char *decbody = (unsigned char *)malloc(blhdr->body_len);
    char bodyhmac[0x14];
    char hdrhmac[0x14];

    // copy the header on to the stack, we dont want to modify anything
    memcpy(&dechdr, blhdr, blhdr->hdr_len);
    
    aes128_cbc_iv_zero_decrypt(hdraeskey, &blhdr->crypteddata, &dechdr.crypteddata, 0x50);

    hmac_sha1(dechdr.crypteddata.iplbodyhmackey, 0x10, &blhdr->bodystart, blhdr->body_len, bodyhmac);
    hmac_sha1(hdrhmackey, 0x10, (unsigned char *)&dechdr, 0x6C, hdrhmac);

    if(verbose) {
        printf("* flash EAP KBL body hmac-sha1: ");
        hexdump(dechdr.crypteddata.iplbodyhmac, 0x14, 0);

        printf("* calculated EAP KBL body hmac-sha1: ");
        hexdump(bodyhmac, 0x14, 0);

        printf("* flash EAP KBL header hmac-sha1: ");
        hexdump(dechdr.crypteddata.headerhmac, 0x14, 0);

        printf("* calculated EAP KBL header hmac-sha1: ");
        hexdump(hdrhmac, 0x14, 0);
    }

    free(decbody);

    return memcmp(bodyhmac, dechdr.crypteddata.iplbodyhmac, sizeof(bodyhmac)) + 
        memcmp(hdrhmac, &dechdr.crypteddata.headerhmac, sizeof(bodyhmac));
}

int decrypt_eap_kbl(unsigned char *flashdata, unsigned char **data, unsigned int *length) {
    struct bldr_hdr *blhdr = flash_locate_eap_kbl(flashdata);
    unsigned char *hdraeskey = keymgr_getkey("eapkblaes", KEY_TYPE_AES_128);
    
    if(verbose) {
        printf("* EAP KBL header aes key: ");
        hexdump(hdraeskey, 0x10, 0);
    }

    struct bldr_hdr dechdr;
    unsigned char *decbody = (unsigned char *)malloc(blhdr->body_len);

    // copy the header on to the stack, we dont want to modify anything
    memcpy(&dechdr, blhdr, blhdr->hdr_len);
    aes128_cbc_iv_zero_decrypt(hdraeskey, &blhdr->crypteddata, &dechdr.crypteddata, 0x50);
    aes128_cbc_iv_zero_decrypt(dechdr.crypteddata.iplbodyaeskey, &blhdr->bodystart, decbody, blhdr->body_len);

    if(data) {
        *data = decbody;
    }

    if(length) {
        *length = blhdr->body_len;
    }

    return 0;
}

int replace_eap_kbl(unsigned char *flashdata, unsigned char *newkbl, int length) {
    struct bldr_hdr *blhdr = flash_locate_eap_kbl(flashdata);
    unsigned char *hdraeskey = keymgr_getkey("eapkblaes", KEY_TYPE_AES_128);
    unsigned char *hdrhmackey = keymgr_getkey("eapkblhmac", KEY_TYPE_HMAC_SHA1);

    if(verbose) {
        printf("* EAP KBL header aes key: ");
        hexdump(hdraeskey, 0x10, 0);

        printf("* EAP KBL header hmac-sha1 key: ");
        hexdump(hdrhmackey, 0x10, 0);
    }

    char bodyhmac[0x14];
    char hdrhmac[0x14];

    // decrypt header
    aes128_cbc_iv_zero_decrypt(hdraeskey, &blhdr->crypteddata, &blhdr->crypteddata, 0x50);

    // encrypt body and replace it in flash
    if(verbose) {
        printf("* old EAP KBL body_len 0x%X\n", blhdr->body_len);
        printf("* new EAP KBL body_len 0x%X\n", length);
    }

    if(blhdr->body_len != length) {
        printf("warning: new EAP KBL has a different body length\n");
    }

    blhdr->body_len = length;
    aes128_cbc_iv_zero_encrypt(blhdr->crypteddata.iplbodyaeskey, newkbl, &blhdr->bodystart, blhdr->body_len);

    // replace body signature
    hmac_sha1(blhdr->crypteddata.iplbodyhmackey, 0x10, &blhdr->bodystart, blhdr->body_len, bodyhmac);

    if(verbose) {
        printf("* old EAP KBL body hmac-sha1: ");
        hexdump(blhdr->crypteddata.iplbodyhmac, 0x14, 0);

        printf("* new EAP KBL body hmac-sha1: ");
        hexdump(bodyhmac, 0x14, 0);
    }

    memcpy(blhdr->crypteddata.iplbodyhmac, bodyhmac, sizeof(bodyhmac));

    // filler null
    memset(blhdr->crypteddata.filler, 0, 8);

    // replace header signature
    hmac_sha1(hdrhmackey, 0x10, (unsigned char *)blhdr, 0x6C, hdrhmac);

    if(verbose) {
        printf("* old EAP KBL header hmac-sha1: ");
        hexdump(blhdr->crypteddata.headerhmac, 0x14, 0);

        printf("* new EAP KBL header hmac-sha1: ");
        hexdump(hdrhmac, 0x14, 0);
    }

    memcpy(blhdr->crypteddata.headerhmac, hdrhmac, sizeof(hdrhmac));

    // encrypt header
    aes128_cbc_iv_zero_encrypt(hdraeskey, &blhdr->crypteddata, &blhdr->crypteddata, 0x50);

    return 0;
}

// TODO: clean up all this bullshit
unsigned int mersenne_twister(int *seed) {
    int var1; // r12
    int *var2; // r1
    unsigned int var3; // r4
    int var4; // r2
    int var5; // r5
    int var6; // r0
    unsigned int var7; // r4
    int *var8; // r5

    var1 = *seed;
    var2 = &seed[*seed + 1];
    var3 = *var2;
    var4 = *seed + 1;
    if(*seed >= 623) {
        var5 = seed[1];
        var4 = 0;
    } else {
        var5 = var2[1];
    }
    *seed = var4;
    var6 = var3 ^ (var3 >> 11);
    var7 = (var3 & 0x80000000 | var5 & 0x7FFFFFFF) >> 1;
    if(var5 & 1 ) {
        var7 ^= 0x9908B0DF;
    }
    var8 = var2 - 227;
    if( var1 < 227 ) {
        var8 = var2 + 397;
    }
    *var2 = var7 ^ *var8;
    
    return var6 ^ (var6 << 7) & 0x9D2C5680 ^ ((var6 ^ (var6 << 7) & 0x9D2C5680) << 15) & 0xEFC60000 ^ ((var6 ^ (var6 << 7) & 0x9D2C5680 ^ ((var6 ^ (var6 << 7) & 0x9D2C5680) << 15) & 0xEFC60000) >> 18);
}

int mersenne_init(int *ptr, unsigned int seed) {
    int *v2; // r4
    signed int v3; // r0
    int v4; // r2
    unsigned int v5; // r1
    unsigned char *v6; // r3
    int v7; // r5
    signed int v8; // r5

    v2 = ptr;
    v3 = 1;
    v4 = 0;
    v2[1] = seed;
    do {
        v5 = seed ^ (seed >> 30);
        v6 = (unsigned char *)&v2[v4];
        v7 = v4++ + 0x6C078965 * v5;
        seed = v3++ + 0x6C078965 * v5;
        *(unsigned int *)(v6 + 8) = v7 + 1;
    } while(v4 != 0x26F);

    v8 = 0x270;
    *v2 = 0;
    do {
        mersenne_twister(v2);
        --v8;
    }
    while(v8);

    return 0;
}

// these starting key values may be specific to a specific version and such?
// I do believe they change them from time to time.
// special thanks to you know who you are if your reading this! :)
unsigned int random_seeds[0x271];
unsigned int eap_keys[8][4] = {
    /* even though these keys are technically public, I cannot post them! */
};

void init_eap_keys() {
    int i;

    mersenne_init(random_seeds,
        eap_keys[7][0] + eap_keys[3][0] + eap_keys[6][0]
        + 2 * (eap_keys[7][1] + eap_keys[3][1] + eap_keys[6][1])
        + 3 * (eap_keys[7][2] + eap_keys[3][2] + eap_keys[6][2])
        + 4 * (eap_keys[7][3] + eap_keys[3][3] + eap_keys[6][3]
    ));

    for(i = 0; i < 4; i++) {
        eap_keys[3][i] ^= mersenne_twister(random_seeds);
        eap_keys[7][i] ^= mersenne_twister(random_seeds);
    }

    mersenne_init(random_seeds,
        eap_keys[4][0] + eap_keys[5][0] + eap_keys[6][0]
        + 2 * (eap_keys[6][1] + eap_keys[5][1] + eap_keys[4][1])
        + 3 * (eap_keys[5][2] + eap_keys[4][2] + eap_keys[6][2])
        + 4 * (eap_keys[4][3] + eap_keys[5][3] + eap_keys[6][3])
    );

    for(i = 0; i < 4; i++) {
        eap_keys[4][i] ^= mersenne_twister(random_seeds);
        eap_keys[5][i] ^= mersenne_twister(random_seeds);
    }

    mersenne_init(random_seeds,
        eap_keys[0][0] + eap_keys[1][0] + eap_keys[2][0]
        + 2 * (eap_keys[1][1] + eap_keys[2][1] + eap_keys[0][1])
        + 3 * (eap_keys[1][2] + eap_keys[2][2] + eap_keys[0][2])
        + 4 * (eap_keys[2][3] + eap_keys[1][3] + eap_keys[0][3])
    );

    for(i = 0; i < 4; i++) {
        eap_keys[1][i] ^= mersenne_twister(random_seeds);
        eap_keys[2][i] ^= mersenne_twister(random_seeds);
    }
}

int decrypt_decompress_eap_kernel(unsigned char *eapkernel, unsigned int eaplength, unsigned char **data, unsigned int *length) {
    struct eap_kernel_storage_hdr *shdr = (struct eap_kernel_storage_hdr *)eapkernel;
    struct eap_kernel_hdr *hdr;
    unsigned char *ptr, *output;
    unsigned int len, outlen;

    if(shdr->magic != EAP_KERNEL_STORAGE_HEADER_MAGIC) {
        printf("error: invalid EAP kernel storage header magic\n");
        return 1;
    }

    ptr = (unsigned char *)malloc(eaplength);
    if(!ptr) {
        printf("error: could not allocate memory for EAP kernel\n");
        return 1;
    }

    memcpy(ptr, eapkernel, eaplength);

    memset(random_seeds, 0, sizeof(random_seeds));
    init_eap_keys();

    // decrypt
    len = 512 - 0x2C;
    len -= len % 0x10;
    aes128_cbc_decrypt(eap_keys[1], ptr + 0x2C, ptr + 0x2C, len, shdr->iv);
    hdr = (struct eap_kernel_hdr *)(ptr + 0x2C);

    if(hdr->magic != EAP_KERNEL_HEADER_MAGIC) {
        printf("error: invalid EAP kernel header magic\n");
        return 1;
    }

    // decrypt
    len = hdr->length;
    len -= hdr->length % 0x10;
    aes128_cbc_decrypt(eap_keys[1], ptr + 0x2C, ptr + 0x2C, len, shdr->iv);

    printf("warning: EAP kernel decryption and decompression will remove the decompressor part of the EAP kernel loading\n");

    // decompress
    output = (unsigned char *)malloc(len);
    outlen = len;
    do {
        outlen *= 2; // resize buffer
        output = realloc(output, outlen);
        len = arzl_decompress(output, outlen, ptr + 0x1D30, NULL);
    } while (len == 0x80560201); // out of space

    arzl_deobfuscate(output, len, 2);

    free(ptr);

    if(data) {
        *data = output;
    } else {
        free(output);
    }

    if(length) {
        *length = len;
    }

    return 0;
}
