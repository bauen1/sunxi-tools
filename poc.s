/* to build:
arm-none-eabi-as poc.s -o poc.o && arm-none-eabi-ld -nostdlib -Ttext=0x20000 --entry=0x20000 poc.o -o poc.elf && arm-none-eabi-objcopy -O binary poc.elf poc.bin
*/

//LENGTH = 0x43000 - 0x20000
//LENGTH = 0x10000 FEL: WORKS
//LENGTH = 0x20000 FEL: WORKS
//LENGTH = 0x28000 FEL: BROKEN
//LENGTH = 0x40000 FEL: BROKEN
//LENGTH = 0x80000 FEL: BROKEN
//LENGTH = 0x23000
//LENGTH = 0x80000
LENGTH = 0x24000
//LENGTH = 0x28000

.ascii "TOC0.GLH"
.word 0x89119800
.word 0x0 /* TOC0_CHECK_SUM */
.word 0x0 /* TOC0_SERIAL_NUM */
.word 0x0 /* TOC0_STATUS */
.word 0x0 /* TOC0_NUM_ITEMS */
.word LENGTH /* TOC0_LENGTH */

/* TOC0_BOOT_MEDIA */
.word 0x0

/* TOC0_RESERVED */
.word 0x0
.word 0x0

/* TOC0_END  */
.ascii "MIE;"

/* 0x20030: */
.global _entry

nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

_entry:
    ldr r0, rtc_addr
    mov r1, #0xCAFE
    str r1, [r0]
    // writel 0x07022000 0x17777777 writel 0x07022010 0x80 # set link led on
    /* 1. set PL7 to output */
    ldr r0, addr
    ldr r1, v0
    str r1, [r0, #0x00]
    /* 2. set output to high */
    mov r1, #0x90
    str r1, [r0, #0x10]
halt:
    b halt

addr:
.word 0x07022000

v0:
.word 0x17717777

rtc_addr:
.word 0x07000100

.fill LENGTH / 4, 4, 0x20030
