// golden

#ifndef _KEYMGR_H
#define _KEYMGR_H

#include "flashtool.h"

#define MAXIMUM_KEYS 4096

/*
... key file format ...
(all fields are little endian)
numkeys - 32 bit integer
[
    keynamelen - 32 bit integer
    keyname - ASCII data for keynamelen
    keytype - 32 bit integer
    keydatalen - 32 bit integer
    keydata - raw key data for keydatalen
] foreach i in range(numkeys)
*/

#define KEY_TYPE_AES_128 0xA1
#define KEY_TYPE_AES_192 0xA2
#define KEY_TYPE_AES_256 0xA3

#define KEY_TYPE_HMAC_SHA1 0xB1
#define KEY_TYPE_RSA_2048_PRIV 0xB2
#define KEY_TYPE_RSA_2048_PUB 0xB3
#define KEY_TYPE_RSA_4096_PRIV 0xB2
#define KEY_TYPE_RSA_4096_PUB 0xB3

struct keymgr_state {
    char **keynames;
    int *keytypes;
    unsigned char **keydata;
    unsigned char *filedata;
    int numkeys;
};

extern struct keymgr_state kmgrstate;

int keymgr_loadkeys(const char *keyfile);
void keymgr_cleanup();
void keymgr_printkeys();
unsigned char *keymgr_getkey(const char *keyname, int keytype);

#endif /* _KEYMGR_H */
