#pragma once

/*
 * glibc's <sys/syscall.h> derives a SYS_<name> from every __NR_<name>
 * the kernel's <asm/unistd.h> defines; these do the same where the libc
 * does not.
 */
#include <sys/syscall.h>

#if !defined(SYS_sigaltstack) && defined(__NR_sigaltstack)
#define SYS_sigaltstack	__NR_sigaltstack
#endif
#if !defined(SYS_uname) && defined(__NR_uname)
#define SYS_uname	__NR_uname
#endif
