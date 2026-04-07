#pragma once

#ifdef __s390x__

#define KERNEL_ADDR	0UL
#define MODULE_ADDR     0x1fffff80000000UL
#define TASK_SIZE	~0UL
#define PAGE_SHIFT	12
#define PTE_FILE_MAX_BITS 59

#define SYSCALLS syscalls_s390x

#else /* __s390x__ */

#define KERNEL_ADDR	0UL
#define TASK_SIZE	0x80000000UL
#define PAGE_SHIFT	12
#define PTE_FILE_MAX_BITS 26

#define SYSCALLS syscalls_s390

#endif /* __s390x__ */

#define PAGE_OFFSET		0x0UL
#define PTRACE_GETREGS		12
#define PTRACE_SETREGS		13
#define PTRACE_GETFPREGS	14
#define PTRACE_SETFPREGS	15
