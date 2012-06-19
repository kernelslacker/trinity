#ifndef _ARCH_SYSCALLS_H
#define _ARCH_SYSCALLS_H 1

#ifdef __x86_64__
#include "syscalls-x86_64.h"
#include "syscalls-i386.h"
#define NR_SYSCALLS NR_X86_64_SYSCALLS
#endif
#ifdef __i386__
#include "syscalls-i386.h"
#define NR_SYSCALLS NR_I386_SYSCALLS
#endif
#ifdef __powerpc__
#include "syscalls-ppc.h"
#define NR_SYSCALLS NR_PPC_SYSCALLS
#endif
#ifdef __ia64__
#include "syscalls-ia64.h"
#endif
#ifdef __sparc__
#include "syscalls-sparc.h"
#endif
#ifdef __arm__
#include "syscalls-arm.h"
#endif

#endif  /* _ARCH_SYSCALLS_H */
