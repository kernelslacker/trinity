#pragma once

#ifdef __x86_64__
#include "syscalls-x86_64.h"
#include "syscalls-i386.h"
#endif
#ifdef __i386__
#include "syscalls-i386.h"
#endif
#ifdef __powerpc__
#include "syscalls-ppc.h"
#endif
#ifdef __ia64__
#include "syscalls-ia64.h"
#endif
#ifdef __sparc__
#include "syscalls-sparc.h"
#endif
#ifdef __s390x__
#include "syscalls-s390x.h"
#endif
#ifdef __s390__
#include "syscalls-s390.h"
#endif
#ifdef __arm__
#include "syscalls-arm.h"
#endif
#ifdef __mips__
#include "syscalls-mips.h"
#endif
#ifdef __sh__
#include "syscalls-sh.h"
#endif
#ifdef __alpha__
#include "syscalls-alpha.h"
#endif
#ifdef __aarch64__
#include "syscalls-aarch64.h"
#endif
#ifdef __hppa__
#include "syscalls-parisc.h"
#endif
#ifdef __tile__
#include "syscalls-tile.h"
#endif
#if defined(__riscv) || defined(__riscv__)
#if __riscv_xlen == 64
#include "syscalls-riscv64.h"
#else
#error "riscv32 is not supported yet."
#endif
#endif
