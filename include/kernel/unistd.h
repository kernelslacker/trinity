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
#if !defined(SYS_statmount) && defined(__NR_statmount)
#define SYS_statmount	__NR_statmount
#endif
#if !defined(SYS_listmount) && defined(__NR_listmount)
#define SYS_listmount	__NR_listmount
#endif
#if !defined(SYS_listxattrat) && defined(__NR_listxattrat)
#define SYS_listxattrat	__NR_listxattrat
#endif
#if !defined(SYS_file_getattr) && defined(__NR_file_getattr)
#define SYS_file_getattr	__NR_file_getattr
#endif
#if !defined(SYS_sysfs) && defined(__NR_sysfs)
#define SYS_sysfs	__NR_sysfs
#endif
#if !defined(SYS_get_robust_list) && defined(__NR_get_robust_list)
#define SYS_get_robust_list	__NR_get_robust_list
#endif
#if !defined(SYS_sched_getattr) && defined(__NR_sched_getattr)
#define SYS_sched_getattr	__NR_sched_getattr
#endif
#if !defined(SYS_lsm_get_self_attr) && defined(__NR_lsm_get_self_attr)
#define SYS_lsm_get_self_attr	__NR_lsm_get_self_attr
#endif
#if !defined(SYS_lsm_list_modules) && defined(__NR_lsm_list_modules)
#define SYS_lsm_list_modules	__NR_lsm_list_modules
#endif
