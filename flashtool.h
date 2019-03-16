// golden

#ifndef _FLASHTOOL_H
#define _FLASHTOOL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <getopt.h>
#include <sys/stat.h>

#include "aes.h"
#include "sha1.h"
#include "hmac-sha1.h"
#include "crypto.h"
#include "keymgr.h"

#include "slb2.h"
#include "nvs.h"
#include "southbridge.h"

#define FLASHTOOL_VERSION "v1.0"
#define FLASHTOOL_CREDITS "golden"
#define FLASHTOOL_KEYFILE "keyfile.bin"

#define FLASH_BLOCK_SIZE 0x200
#define FLASH_SIZE 0x2000000
#define FLASH_NUMBLOCKS (FLASH_SIZE / FLASH_BLOCK_SIZE)

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

struct consolemap_entry {
    char *model; // model sometimes has a component like B01 or B01X, leave that off
    char *southbridge;
    //char *keyfile;
};

struct codename_entry {
    char *codename;
    char *realname;
    char *comment;
};

extern int verbose;
extern int noverify;
extern struct consolemap_entry g_consolemap[];
extern struct codename_entry g_codenames[];

#define NUM_CONSOLES (sizeof(g_consolemap) / sizeof(g_consolemap[0]))
#define NUM_CODENAMES (sizeof(g_codenames) / sizeof(g_codenames[0]))

struct consolemap_entry *find_consolemap(char *model);
struct codename_entry *find_codename(char *codename);

void hexdump(unsigned char *data, int length, int newlines);
int dumpbin(unsigned char *filename, unsigned char *data, int length);

#endif /* _FLASHTOOL_H */
