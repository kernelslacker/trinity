#pragma once

/*
 * Wrapper around <linux/ptrace.h> that ships #ifndef-guarded fallbacks
 * for the PTRACE_* request ids added after trinity's original
 * definitions.  Build hosts whose installed uapi header is older than
 * the upstream kernel silently miss the newer ids; the fallback values
 * match the upstream uapi numbering so the request ids the kernel
 * parses match the ones the syscall generator emits.
 */
#include <linux/ptrace.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE			0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT		0x4207
#endif
#ifndef PTRACE_LISTEN
#define PTRACE_LISTEN			0x4208
#endif
#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER	0x420c
#endif
#ifndef PTRACE_SECCOMP_GET_METADATA
#define PTRACE_SECCOMP_GET_METADATA	0x420d
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO		0x420e
#endif
#ifndef PTRACE_GET_RSEQ_CONFIGURATION
#define PTRACE_GET_RSEQ_CONFIGURATION	0x420f
#endif

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x4202
#define PTRACE_GET_SYSCALL_INFO_SIZE (8 + 6*8)
#endif
#ifndef PTRACE_GET_RSEQ_CONFIGURATION
#define PTRACE_GET_RSEQ_CONFIGURATION 0x420f
#endif

