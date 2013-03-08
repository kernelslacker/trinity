#ifdef __s390x__

#define KERNEL_ADDR	0UL
#define MODULE_ADDR     0xffffffffa0000000L	// FIXME: Placeholder
#define TASK_SIZE	~0UL
#define PAGE_SHIFT	12
#define PTE_FILE_MAX_BITS 59

#else /* __s390x__ */

#define KERNEL_ADDR	0UL
#define TASK_SIZE	0x80000000UL
#define PAGE_SHIFT	12
#define PTE_FILE_MAX_BITS 26

#endif /* __s390x__ */

#define PTRACE_GETREGS		0
#define PTRACE_GETFPREGS	0
#define PTRACE_SETREGS		0
#define PTRACE_SETFPREGS	0
