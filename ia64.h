#define KERNEL_ADDR	0xa000000100000000
#define PAGE_OFFSET 0xe000000000000000
#define TASK_SIZE 0xa000000000000000

#define PAGE_SHIFT 		12
#define PAGE_SIZE               (__IA64_UL_CONST(1) << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE - 1))
#define PTE_FILE_MAX_BITS	61

// for __IA64_UL_CONST we need to include:
#include <asm/types.h>
