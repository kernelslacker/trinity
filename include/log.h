#pragma once

#include <unistd.h>
#include "config.h"
#include "exit.h"
#include "shm.h"
#include "syscall.h"
#include "types.h"
#include "utils.h"

extern char ANSI_RED[];
extern char ANSI_GREEN[];
extern char ANSI_YELLOW[];
extern char ANSI_BLUE[];
extern char ANSI_MAGENTA[];
extern char ANSI_CYAN[];
extern char ANSI_WHITE[];
extern char ANSI_RESET[];

#define MAX_LOGLEVEL 3

FILE *robust_find_logfile_handle(void);
unsigned int highest_logfile(void);
void synclogs(void);

void strip_ansi(char *ansibuf, unsigned int buflen);

void output(unsigned char level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void output_syscall_prefix(struct syscallrecord *rec);
void output_syscall_postfix(struct syscallrecord *rec);

void open_logfiles(void);
void close_logfiles(void);
void debugf(const char *fmt, ...);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define unreachable() do { } while (1)

extern void __BUG(const char *bugtxt, const char *filename, const char *funcname, unsigned int lineno);

#define BUG(bugtxt)	{ \
	__BUG(bugtxt, __FILE__, __func__, __LINE__); \
	unreachable(); \
}

#define BUG_ON(condition)	do { if ((condition)) BUG(__stringify(condition)); } while (0)
