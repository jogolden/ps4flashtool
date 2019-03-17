// golden
#include "flashtool.h"

int verbose;
int noverify;

// any text with a ? is a wildcard
struct consolemap_entry g_consolemap[] = {
    { "CUH-10??A B01", "CXD900025G" }, // Aeolia
    { "CUH-11??A B01", "CXD900025G" }, // Aeolia
    { "CUH-12??A B01X", "CXD900036G" }, // ?Aeolia?
    { "CUH-21??A", "CXD900042G" }, // ?Balaik?
    { "", "CXD900044G" }, // Belize
    { NULL, NULL }
};

struct codename_entry g_codenames[] = {
    { "40000001", "BLNK", "syscon firmware" },
    { "40000002", "BASE", "syscon firmware" },
    { "40000003", "SYST", "syscon firmware" },
    { "40010001", "PTCH", "syscon patch 1" },
    { "40010002", "PTCH", "syscon patch 2" },
    { "40020001", "USB", "USB-STAT firmware update" },
    { "40030001", "CP", "CP firmware" },
    { "80000001", "SAM_IPL", "SAMU initial program loader"},
    { "80010001", "SAM_SECKRN", "SAMU secure kernel"},
    { "80010002", "APU_FIRMS", "x86-kernel/vbios/gpufw"},
    { "80010006", "SAM_ACMGR", "SAMU module"},
    { "80010008", "SAM_AUTHMGR", "SAMU module"},
    { "80010009", "SAM_IDMGR", "SAMU module"},
    { "8001000A", "SAM_FSMMGR", "SAMU module"},
    { "8001000B", "SAM_KEYMGR", "SAMU module"},
    { "8001000C", "SAM_SERVICE", "SAMU module"},
    { "C0000001", "EMC_IPL", "EMC initial program loader" },
    { "C0010001", "EAP_KBL", "EAP kernel bootloader" },
    { "C0020001", "TORUS_FW", "wifi/bluetooth soc firmware" },
    { NULL, NULL, NULL }
};

struct consolemap_entry *find_consolemap(char *model) {
    int i, k;
    int good;
    char *m;

    for(i = 0; i < NUM_CONSOLES; i++) {
        m = g_consolemap[i].model;

        // loop and take wildcard into account
        good = 0;
        for(k = 0; k < MIN(strlen(m), strlen(model)); k++) {
            if(m[k] == '?' || m[k] == model[k]) {
                good = 1;
            } else {
                good = 0;
                break;
            }
        }

        if(good) {
            return &g_consolemap[i];
        }
    }

    return NULL;
}

struct codename_entry *find_codename(char *codename) {
    int i;

    for(i = 0; i < NUM_CODENAMES; i++) {
        if(!strcmp(g_codenames[i].codename, codename)) {
            return &g_codenames[i];
        }
    }

    return NULL;
}

void hexdump(unsigned char *data, int length, int newlines) {
    int i, k;

    for(i = 0; i < length; i++) {
        printf("%02X ", data[i]);

        if(newlines) {
            if(i != 0 && (i + 1) % 16 == 0) {
                printf("\n");
            }
        }
    }

    printf("\n");
}

int dumpbin(unsigned char *filename, unsigned char *data, int length) {
    FILE *fp;

    fp = fopen(filename, "wb");
    if(!fp) {
        return 1;
    }
    
    fwrite(data, 1, length, fp);
    fclose(fp);

    return 0;
}

int readbin(unsigned char *filename, unsigned char **data, int *length) {
    FILE *fp;
    unsigned char *ptr;
    long size;

    fp = fopen(filename, "rb");
    if(!fp) {
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    ptr = (unsigned char *)malloc(size);
    if(!ptr) {
        return 1;
    }

    memset(ptr, 0, size);
    fread(ptr, 1, size, fp);
    fclose(fp);

    if(data) {
        *data = ptr;
    } else {
        free(ptr);
    }

    if(length) {
        *length = size;
    }

    return 0;
}

unsigned char *load_flashdump(char *flashfile) {
    FILE *fp;
    unsigned char *data;
    int length;

    printf("loading flash dump '%s' ...\n", flashfile);

    if(readbin(flashfile, &data, &length)) {
        return NULL;
    }

    if(length != FLASH_SIZE) {
        printf("warning: flash size mismatch. is your flash really 32MB?\n");
    }

    return data;
}

void print_flashinfo(unsigned char *flashdata) {
    struct nvs_console_info cinfo;
    char macaddress[6];
    int i;

    // read console info and mac address
    nvs_read(flashdata, 0, 2, NVS_VAR_BLOCK2_CONSOLE_INF0, sizeof(cinfo), (unsigned char *)&cinfo);
    nvs_read(flashdata, 0, 0, NVS_VAR_BLOCK0_MAC_ADDRESS, sizeof(macaddress), macaddress);

    printf("* motherboard serial: %.*s\n", (int)sizeof(cinfo.moboserial), cinfo.moboserial);
    printf("* serial: %.*s\n", (int)sizeof(cinfo.serial), cinfo.serial);
    printf("* model: %.*s\n", (int)sizeof(cinfo.model), cinfo.model);
    printf("* mac address: ");
    for(i = 0; i < sizeof(macaddress); i++) {
        printf("%02X%c", macaddress[i] & 0xFF, (i == sizeof(macaddress) - 1) ? '\n' : ':');
    }

    printf("\n");
}

int check_flashdump(unsigned char *flashdata) {
    printf("warning: verification of the flash data is only for EMC IPL and EAP KBL.\n");
    return verify_emc_ipl(flashdata) == 1 || verify_eap_kbl(flashdata) == 1;
}

int extract_flashdump(unsigned char *flashdata, char *extractdir) {
    unsigned char *ptr;
    int len;
    char path[512];
    
    printf("extracting flash to '%s' directory ...\n", extractdir);
    
    mkdir(extractdir, S_IRWXU);

    snprintf(path, sizeof(path), "%s/%s", extractdir, "emcipl.bin");
    if(decrypt_emc_ipl(flashdata, &ptr, &len)) {
        return 1;
    }

    dumpbin(path, ptr, len);
    free(ptr);

    printf("extracted EMC IPL to '%s'!\n", path);

    snprintf(path, sizeof(path), "%s/%s", extractdir, "eapkbl.elf");
    if(decrypt_eap_kbl(flashdata, &ptr, &len)) {
        return 1;
    }

    dumpbin(path, ptr, len);
    free(ptr);
    
    printf("extracted EAP KBL to '%s'!\n", path);

    return 0;
}

void print_usage() {
    char strbuffer[1024];

    printf("Usage: flashtool [option(s)]\n");
    printf("Examples:\n");
    printf("\tflashtool --extract dumps -i flashdump.bin\n");
    printf("\tflashtool --emcipl patchedipl.bin -k CXD44G.keys --input flashdump.bin --output flashout.bin\n");
    printf("\tflashtool --eapkbl patchedkbl.bin -k cec_h4x_sram_dmp_CXD36G.keys --input flashdump.bin --output flashout.bin\n");
    printf("\tflashtool -k CXD42G.keys -v -n --input flashdump.bin\n");
    printf("\tflashtool --extract dumps -n --input flashdump.bin\n");
    printf("\tflashtool --eapkern eapkern_hdd_enc.bin,eapkern_hdd_dec.bin\n");
    printf("Options:\n");

    #define PRINT_OPTION(short, long, hasarg, arg, comment) if(hasarg) { \
                snprintf(strbuffer, sizeof(strbuffer), "\t-%s [%s], --%s [%s]", short, arg, long, arg); \
            } else { \
                snprintf(strbuffer, sizeof(strbuffer), "\t-%s, --%s", short, long); \
            } printf("%s %*s\n", strbuffer, (int)(80 - strlen(strbuffer)), comment);
    #define PRINT_LONG_OPTION(long, hasarg, arg, comment) if(hasarg) { \
                snprintf(strbuffer, sizeof(strbuffer), "\t--%s [%s]", long, arg); \
            } else { \
                snprintf(strbuffer, sizeof(strbuffer), "\t--%s", long); \
            } printf("%s %*s\n", strbuffer, (int)(80 - strlen(strbuffer)), comment);

    PRINT_OPTION("h", "help", 0, "", "show this help message")
    PRINT_OPTION("v", "verbose", 0, "", "verbose output")
    PRINT_OPTION("i", "input", 1, "flash", "flash file input")
    PRINT_OPTION("o", "output", 1, "flash", "flash file output")
    PRINT_OPTION("n", "noverify", 0, "", "do not verify the flash signatures")
    PRINT_OPTION("k", "keyfile", 0, "", "override the default key file")
    PRINT_LONG_OPTION("extract", 1, "dir", "extract files to directory")
    PRINT_LONG_OPTION("emcipl", 1, "emcipl", "replace EMC IPL (initial program loader)")
    PRINT_LONG_OPTION("eapkbl", 1, "eapkbl", "replace EAP KBL (kernel boot loader)")
    PRINT_LONG_OPTION("eapkern", 1, "input,output", "decrypt the EAP kernel")

    printf("\n");
    printf("Everything you can replace in the flash is resigned when you replace it.\n");
    printf("Also, when the extract option is enabled, the files will be extracted after the replacement/resigning.\n");
    printf("!! This tool will never overwrite your existing flash dump file! You must specify an output. !!\n");
}

int main(int argc, char **argv) {
    int i;
    char *flashfile = NULL;
    char *flashout = NULL;
    char *extractdir = NULL;
    char *emcipl = NULL;
    char *eapkbl = NULL;
    char *eapkern = NULL;

    char *keyfile = FLASHTOOL_KEYFILE;
    unsigned char *flashdata = NULL;
    unsigned char *ptr = NULL, *ptr2 = NULL;
    unsigned int len, len2;

    printf("~ PlayStation 4 flash tool " FLASHTOOL_VERSION " | by " FLASHTOOL_CREDITS " ~\n");

    if(argc == 1) {
        printf("try '%s --help' for more information\n", argv[0]);
        return 0;
    }

    // make sure this is zero
    verbose = 0;
    noverify = 0;

    for(i = 1; i < argc; i++) {
        char *opt = argv[i];
        char *arg = (i == argc - 1) ? NULL : argv[i + 1];

        if(opt[0] != '-') {
            printf("error: invalid argument syntax!\n");
            return 1;
        }
        if(opt[0] == '-') { opt++; }
        if(opt[0] == '-') { opt++; }
        
        if(opt[0] == 'h' || !strcmp(opt, "help")) {
            print_usage();
            return 1;
        } else if(opt[0] == 'v' || !strcmp(opt, "verbose")) {
            verbose = 1;
        } else if(opt[0] == 'i' || !strcmp(opt, "input")) {
            if(!arg) {
                printf("error: invalid flash input argument!\n");
                return 1;
            }
            flashfile = arg;
            i++;
        } else if(opt[0] == 'o' || !strcmp(opt, "output")) {
            if(!arg) {
                printf("error: invalid flash output argument!\n");
                return 1;
            }
            flashout = arg;
            i++;
        } else if(opt[0] == 'n' || !strcmp(opt, "noverify")) {
            noverify = 1;
        } else if(opt[0] == 'k' || !strcmp(opt, "keyfile")) {
            if(!arg) {
                printf("error: invalid keyfile argument!\n");
                return 1;
            }
            keyfile = arg;
            printf("* changed keyfile to '%s'\n", keyfile);
            i++;
        } else if(!strcmp(opt, "extract")) {
            if(!arg) {
                printf("error: invalid extract directory argument!\n");
                return 1;
            }
            extractdir = arg;
            i++;
        } else if(!strcmp(opt, "emcipl")) {
            if(!arg) {
                printf("error: invalid emcipl argument!\n");
                return 1;
            }
            emcipl = arg;
            i++;
        } else if(!strcmp(opt, "eapkbl")) {
            if(!arg) {
                printf("error: invalid eapkbl argument!\n");
                return 1;
            }
            eapkbl = arg;
            i++;
        } else if(!strcmp(opt, "eapkern")) {
            if(!arg) {
                printf("error: invalid eapkern argument!\n");
                return 1;
            }
            eapkern = arg;
            i++;
        } else {
            printf("error: unknown option '%s'\n", opt);
            printf("try '%s --help' for more information\n", argv[0]);
            return 1;
        }
    }

    if(eapkern) {
        char *comma = strstr(eapkern, ",");
        if(!comma) {
            printf("error: please use a comma between the input and output for EAP kernel decryption\n");
            goto end;
        }

        comma[0] = '\0';

        char *input = eapkern;
        char *output = comma + 1;
        
        if(readbin(input, &ptr, &len)) {
            printf("error: failed to read EAP kernel from file!\n");
            goto end;
        }

        printf("attempting to decrypt EAP kernel '%s' to '%s' ...\n", input, output);
        printf("* keys may or not work on your console model/firmware version\n");

        if(decrypt_decompress_eap_kernel(ptr, len, &ptr2, &len2)) {
            printf("error: failed to decrypt EAP kernel\n");
            goto end;
        }

        dumpbin(output, ptr2, len2);

        printf("wrote decrypted EAP kernel\n");

        free(ptr);
        free(ptr2);

        goto end;
    }

    // load the keys
    printf("loading key file '%s' ...\n", keyfile);
    if(keymgr_loadkeys(keyfile)) {
        return 1;
    }

    if(verbose) {
        keymgr_printkeys();
    }

    if(!flashfile) {
        printf("error: please specify a PlayStation 4 flash file!\n");
        goto end;
    }
    
    // load flash
    flashdata = load_flashdump(flashfile);
    if(!flashdata) {
        printf("error: invalid flash file!\n");
        goto end;
    }
    
    print_flashinfo(flashdata);

    if(verbose) {
        find_and_print_slb2_info(flashdata);
    }
    
    // check flash
    if(!noverify) {
        if(check_flashdump(flashdata)) {
            printf("error: invalid flash data detected!\n");
            goto end;
        }
    }
    
    // replace emc ipl
    if(emcipl) {
        printf("replacing EMC IPL in flash dump with '%s' ...\n", emcipl);

        if(readbin(emcipl, &ptr, &len)) {
            printf("error: failed to read EMC IPL from file!\n");
            goto end;
        }

        if(replace_emc_ipl(flashdata, ptr, len)) {
            printf("warning: failed to replace EMC IPL!\n");
        }

        free(ptr);
    }
    
    // replace eap kbl
    if(eapkbl) {
        printf("replacing EAP KBL in flash dump with '%s' ...\n", eapkbl);

        if(readbin(eapkbl, &ptr, &len)) {
            printf("error: failed to read EAP KBL from file!\n");
            goto end;
        }

        if(replace_eap_kbl(flashdata, ptr, len)) {
            printf("warning: failed to replace EAP KBL!\n");
        }

        free(ptr);
    }
    
    // extract parts
    if(extractdir) {
        if(extract_flashdump(flashdata, extractdir)) {
            printf("error: failed during flash extraction!\n");
            goto end;
        }
    }

    // write flashdata out
    if(flashout) {
        // enable uart ;)
        char uart = 1;
        nvs_write(flashdata, 0, 4, NVS_VAR_BLOCK4_ENABLE_UART, 1, &uart);

        if(verbose) {
            printf("* enabled uart in NVS region\n");
        }

        dumpbin(flashout, flashdata, FLASH_SIZE);
        printf("wrote final flash to '%s'\n", flashout);
    }

end:
    if(flashdata) {
        free(flashdata);
    }

    keymgr_cleanup();

    return 0;
}
 
