// golden

#include "keymgr.h"

struct keymgr_state kmgrstate;

int keymgr_loadkeys(const char *keyfile) {
    FILE *fkeyfile;
    long filesize;
    unsigned char *ptr;
    int i;
    int sz;

    fkeyfile = fopen(keyfile, "rb");
    if(!fkeyfile) {
        printf("keymgr: invalid key file!\n");
        return 1;
    }

    kmgrstate.keynames = (char **)malloc(MAXIMUM_KEYS * sizeof(char *));
    kmgrstate.keytypes = (int *)malloc(MAXIMUM_KEYS * sizeof(int));
    kmgrstate.keydata = (unsigned char **)malloc(MAXIMUM_KEYS * sizeof(char *));

    fseek(fkeyfile, 0, SEEK_END);
    filesize = ftell(fkeyfile);
    fseek(fkeyfile, 0, SEEK_SET);

    kmgrstate.filedata = (char *)malloc(filesize);
    fread(kmgrstate.filedata, 1, filesize, fkeyfile);
    fclose(fkeyfile);

    // parse all the keys
    ptr = kmgrstate.filedata;
    kmgrstate.numkeys = *(unsigned int *)ptr;
    ptr += 4;

    for(i = 0; i < kmgrstate.numkeys; i++) {
        // name
        sz = *(unsigned int *)ptr; ptr += 4;
        kmgrstate.keynames[i] = ptr; ptr += sz;

        // keytype
        kmgrstate.keytypes[i] = *(unsigned int *)ptr; ptr += 4;

        // keydat
        sz = *(unsigned int *)ptr; ptr += 4;
        kmgrstate.keydata[i] = ptr; ptr += sz;
    }

    return 0;
}

void keymgr_cleanup() {
    if(kmgrstate.keynames) {
        free(kmgrstate.keynames);
    }

    if(kmgrstate.keytypes) {
        free(kmgrstate.keytypes);
    }

    if(kmgrstate.keydata) {
        free(kmgrstate.keydata);
    }

    if(kmgrstate.filedata) {
        free(kmgrstate.filedata);
    }
}

void keymgr_printkeys() {
    int i;

    printf("\nkey manager state:\n");
    for(i = 0; i < kmgrstate.numkeys; i++) {
        printf("\tname: '%s' keytype: 0x%X\n", kmgrstate.keynames[i], kmgrstate.keytypes[i]);
        //hexdump(kmgrstate.keydata[i], 0x10);
    }
    printf("\n");
}

unsigned char *keymgr_getkey(const char *keyname, int keytype) {
    int i;

    for(i = 0; i < kmgrstate.numkeys; i++) {
        if(!strcmp(kmgrstate.keynames[i], keyname) && kmgrstate.keytypes[i] == keytype) {
            return kmgrstate.keydata[i];
        }
    }

    return NULL;
}
