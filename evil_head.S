.section "toc0_header"

.byte 0x54, 0x4f, 0x43, 0x30
.byte 0x2e, 0x47, 0x4c, 0x48
.word 0x89119800
.word 0
.word 0
.word 0
.word 0 /* num items */

/* length, rough approximation */
.word 0x44000
.word 0 /* boot media */


.section "myentry"
.extern main
    b main

.section "overflow"
/* now we fill the (possibly) stack memory with our entry address */
/* roughly right */
.fill (0x54000 - 0x15000)/ 4, 4, 0x15000
