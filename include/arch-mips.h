#pragma once

#define KERNEL_ADDR 0xc0100220
#define MODULE_ADDR 0xa0000000	// FIXME: Placeholder
#define PAGE_OFFSET 0x80000000
#define TASK_SIZE (PAGE_OFFSET)
#define PAGE_SHIFT 12
#define PTE_FILE_MAX_BITS 31

#if _MIPS_SIM == _ABIO32
#define SYSCALL_OFFSET 4000
#elif _MIPS_SIM == _ABIN32
#define SYSCALL_OFFSET 6000
#elif _MIPS_SIM == _ABI64
#define SYSCALL_OFFSET 5000
#endif

#define SYSCALLS syscalls_mips
