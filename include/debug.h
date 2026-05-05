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

void syslogf(const char *fmt, ...);
