### PlayStation 4 Flash Tool by golden

```
~ PlayStation 4 flash tool v1.0 | by golden ~
Usage: flashtool [option(s)]
Examples:
        flashtool --extract dumps -i flashdump.bin
        flashtool --emcipl patchedipl.bin -k CXD44G.keys --input flashdump.bin --output flashout.bin
        flashtool --eapkbl patchedkbl.bin -k cec_h4x_sram_dmp_CXD36G.keys --input flashdump.bin --output flashout.bin
        flashtool -k CXD42G.keys -v -n --input flashdump.bin
        flashtool --extract dumps -n --input flashdump.bin
        flashtool --eapkern eapkern_hdd_enc.bin,eapkern_hdd_dec.bin
Options:
        -h, --help                                                show this help message
        -v, --verbose                                                     verbose output
        -i [flash], --input [flash]                                     flash file input
        -o [flash], --output [flash]                                   flash file output
        -n, --noverify                                do not verify the flash signatures
        -k, --keyfile                                      override the default key file
        --extract [dir]                                       extract files to directory
        --emcipl [emcipl]                       replace EMC IPL (initial program loader)
        --eapkbl [eapkbl]                           replace EAP KBL (kernel boot loader)
        --eapkern [input,output]                                  decrypt the EAP kernel

Everything you can replace in the flash is resigned when you replace it.
Also, when the extract option is enabled, the files will be extracted after the replacement/resigning.
!! This tool will never overwrite your existing flash dump file! You must specify an output. !!
```

__This release includes no keys and I will never release keys.__

You must create your own keyfile if you have keys. Look at `keymgr.h` for the format.  
Look at the fail0verflow article if you want to try and derive the keys yourself.
There may be some bugs with this release.

Shoutout to Team Molecule for ARZL decompress, zecoxao for some NVS information on the wiki, SKFU and iqd for SLB2, and many anonymous contributors!
