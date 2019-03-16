// golden

#ifndef _SLB2_H
#define _SLB2_H

// credits to skfu and iqd

#include "flashtool.h"

#define SLB2_MAGIC 0x32424C53

struct slb2_entry {
	unsigned int block_offset;
	unsigned int file_size;
	unsigned int alignment[2];
	char file_name[32];
} __attribute__((packed));
 
struct slb2_header {
	unsigned int magic;
	unsigned int version;
	unsigned int flags;
	unsigned int file_count;
	unsigned int block_count;
	unsigned int reserved[3];
	struct slb2_entry entry_list[0];
} __attribute__((packed));

static void find_and_print_slb2_info(unsigned char *flashdata) {
    struct slb2_header *hdr;
    struct slb2_entry *entry;
    unsigned char *ptr;
    int i, k;

    ptr = (unsigned char *)flashdata;

    while(ptr < (unsigned char *)(flashdata + 0x2000000)) {
        if(*(unsigned int *)ptr == SLB2_MAGIC) {
            hdr = (struct slb2_header *)ptr;

            printf("* found slb2_header at 0x%llX\n", (unsigned long long)(ptr - flashdata));

            for(k = 0; k < hdr->file_count; k++) {
                entry = &hdr->entry_list[k];
                printf("\tfile_name: %s block_offset: 0x%X file_size 0x%X\n", entry->file_name, entry->block_offset, entry->file_size);
            }
        }

        ptr += 4;
    }

    printf("\n");
}

#endif /* _SLB2_H */
