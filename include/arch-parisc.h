#pragma once

// userspace is always 32 bit on parisc

#define PAGE_OFFSET 0x10000000

#if 0
// for 64 bit
#define PAGE_OFFSET 0x40000000
#endif

#define KERNEL_ADDR	0x10100000
#define MODULE_ADDR     0x10000L	// TODO: runtime-dependent (parisc_vmalloc_start), this is an approximation
#define TASK_SIZE 0xFFF00000

#define PAGE_SHIFT 		12
#define PTE_FILE_MAX_BITS	(32 - 11)

#define PTRACE_GETREGS		18
#define PTRACE_GETFPREGS	14
#define PTRACE_SETREGS		19
#define PTRACE_SETFPREGS	15

#define SYSCALLS syscalls_parisc
