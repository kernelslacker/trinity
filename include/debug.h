#pragma once

#include "child.h"
#include "syscall.h"
#include "utils.h"

void show_backtrace(void);

extern void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno)
	__attribute__((noreturn));

#define BUG(bugtxt)	do { \
	__BUG(bugtxt, __FILE__, __func__, __LINE__); \
	unreachable(); \
} while (0)

#define BUG_ON(condition)	do { if ((condition)) BUG(__stringify(condition)); } while (0)

void dump_childdata(struct childdata *child);
void dump_syscallrec(struct syscallrecord *rec);

/*
 * Surface a child-context __BUG() event to the real (parent) stderr.
 * Idempotent via the child->bug_dumped cmpxchg gate: simultaneous
 * pollers print exactly one copy.  Re-symbolises child->bug_backtrace
 * in parent context (libc-touchy, fine here -- not async-signal-safe
 * but never called from a signal handler) and drains
 * child->pre_crash_ring.  Called from the main_loop per-tick poll.
 */
void dump_child_bug(struct childdata *child);

void syslogf(const char *fmt, ...);
