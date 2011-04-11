#define KERNEL_ADDR	0xc0100220

#define PAGE_OFFSET 0xC0000000
#define TASK_SIZE (PAGE_OFFSET)
/*
 * Alternative possibilities for PAGE_OFFSET:
 * default 0xB0000000 if VMSPLIT_3G_OPT
 * default 0x78000000 if VMSPLIT_2G
 * default 0x40000000 if VMSPLIT_1G
 */

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define PTE_FILE_MAX_BITS 32

