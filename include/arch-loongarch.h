#pragma once

#define KERNEL_ADDR 0x9000000000000000
#define MODULE_ADDR 0xffff800000000000
#define PAGE_OFFSET 0x9000000000000000
#define TASK_SIZE (PAGE_OFFSET)

#define PAGE_SHIFT 14
#define PTE_FILE_MAX_BITS 31

#define PTRACE_GETREGS          0
#define PTRACE_GETFPREGS        0
#define PTRACE_SETREGS          0
#define PTRACE_SETFPREGS        0

#define SYSCALLS syscalls_loongarch
