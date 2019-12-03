#pragma once

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC             0x0001U
#define MFD_ALLOW_SEALING       0x0002U
#define MFD_HUGETLB		0x0004U
#endif

// FIXME: Keep all this here until glibc supports it.
#ifndef SYS_memfd_create
#ifdef __x86_64__
#define SYS_memfd_create 319
#endif
#ifdef __i386__
#define SYS_memfd_create 356
#endif
#ifdef __sparc__
#define SYS_memfd_create 348
#endif
#ifdef __ia64__
#define SYS_memfd_create 1340
#endif
#endif
