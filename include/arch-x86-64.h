#pragma once

#define X86 1

#define PAGE_OFFSET	0xffff880000000000UL
#define KERNEL_ADDR	0xffffffff81000000UL
#define MODULE_ADDR	0xffffffffa0000000UL
#define VDSO_ADDR	0xffffffffff600000UL

#define TASK_SIZE       (0x800000000000UL - 4096)

#define PAGE_SHIFT 12

#define PTE_FILE_MAX_BITS 32

#define ARCH_IS_BIARCH 1
#define SYSCALLS32 syscalls_i386
#define SYSCALLS64 syscalls_x86_64

#define DO_32_SYSCALL \
	__asm__ volatile ( \
		"pushq %%rbp\n\t" \
		"pushq %%r8\n\t" \
		"pushq %%r9\n\t" \
		"pushq %%r10\n\t" \
		"pushq %%r11\n\t" \
		"movq %7, %%rbp\n\t" \
		"int $0x80\n\t" \
		"popq %%r11\n\t" \
		"popq %%r10\n\t" \
		"popq %%r9\n\t" \
		"popq %%r8\n\t" \
		"popq %%rbp\n\t" \
		: "=a" (__res) \
		: "0" (call),"b" ((long)(a1)),"c" ((long)(a2)),"d" ((long)(a3)), "S" ((long)(a4)),"D" ((long)(a5)), "g" ((long)(a6)) \
		: "%rbp" /* mark EBP reg as dirty */ \
	);
