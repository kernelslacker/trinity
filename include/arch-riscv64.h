#pragma once

/* Sv39 layout; the other paging modes only move the kernel-half bases. */
#define PAGE_OFFSET		0xffffffd800000000UL
#define TASK_SIZE		(1UL << 38)
#define MODULE_ADDR		0xffffffff00000000UL
#define KERNEL_ADDR		0xffffffff80000000UL

#define PAGE_SHIFT		12

#define SYSCALLS syscalls_riscv64

#define PTRACE_GETREGS		12
#define PTRACE_SETREGS		13
#define PTRACE_GETFPREGS	14
#define PTRACE_SETFPREGS	15
