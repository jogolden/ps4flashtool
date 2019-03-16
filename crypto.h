// golden

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "flashtool.h"

int aes128_cbc_encrypt(void *key, void *plaintext, void *ciphertext, int length, void *iv);
int aes128_cbc_decrypt(void *key, void *ciphertext, void *plaintext, int length, void *iv);

int aes128_cbc_iv_zero_encrypt(void *key, void *plaintext, void *ciphertext, int length);
int aes128_cbc_iv_zero_decrypt(void *key, void *ciphertext, void *plaintext, int length);

// credits to team molecule here, even though its a C+P from IDA lol
int arzl_decompress(unsigned char *buffer, unsigned int buflen, const unsigned char *input, const unsigned char **endptr);
int arzl_deobfuscate(unsigned char *buffer, int len, int version);

#endif /* _CRYPTO_H */
