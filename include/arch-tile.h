#pragma once

#ifdef __tilegx__

#define MAX_VA_WIDTH   42
#define MAX_PA_WIDTH   40

#define PAGE_OFFSET            (-(1 << (MAX_VA_WIDTH - 1)))
#define KERNEL_HIGH_VADDR       0xfffffff800000000  /* high 32GB */
#define MEM_SV_START            (KERNEL_HIGH_VADDR - 0x100000000) /* 256 MB */
#define MEM_MODULE_START        (MEM_SV_START + (256*1024*1024)) /* 256 MB */
#define MEM_MODULE_END          (MEM_MODULE_START + (256*1024*1024))
#define KERNEL_ADDR            MEM_SV_START
#define MODULE_ADDR            MEM_MODULE_START

#define TASK_SIZE_MAX           (1 << (MAX_VA_WIDTH - 1))
#define TASK_SIZE               TASK_SIZE_MAX

#define PAGE_SHIFT     16
#define PTE_FILE_MAX_BITS 32
#define BITS_PER_LONG  64

#endif

#define SYSCALLS syscalls_tile
