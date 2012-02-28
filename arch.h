#ifndef _ARCH_H
#define _ARCH_H 1

#ifdef __x86_64__
#include "x86-64.h"
#endif
#ifdef __i386__
#include "i386.h"
#endif
#ifdef __powerpc__
#include "ppc.h"
#endif
#ifdef __ia64__
#include "ia64.h"
#endif
#ifdef __sparc__
#include "sparc.h"
#endif

#define PAGE_MASK (~(page_size - 1))

#endif  /* _ARCH_H */
