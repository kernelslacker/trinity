#ifdef __arch64__
#define KERNEL_ADDR	0xfffff80000000000
#define TASK_SIZE ~0UL
#else
#define KERNEL_ADDR	0xf0000000
#define TASK_SIZE 0xF0000000UL
#endif
