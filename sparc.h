#include "syscalls-sparc.h"

#ifdef __arch64__
#define KERNEL_ADDR	0xfffff80000000000
#else
#define KERNEL_ADDR	0xf0000000
#endif
