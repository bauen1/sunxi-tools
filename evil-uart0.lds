SECTIONS
{
    /* h5 */
    . = 0x10000;
    toc0_start = .;
    .text : {
        *(toc0_header)
        . = 0x15000;
        *(myentry)
        *(.text)
        *(overflow)
    }
    toc0_end = .;
}
