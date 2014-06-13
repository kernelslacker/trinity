#pragma once

#include <unistd.h>
#include "config.h"
#include "exit.h"
#include "params.h"	// monochrome
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

#define BUGTXT "BUG!: " VERSION

#define BUG(bugtxt)	{ \
	printf("[%d] %s:%s:%d %s%s%s", getpid(), __FILE__, __func__, __LINE__, ANSI_RED, bugtxt, ANSI_RESET); \
	show_backtrace();	\
	while(1) { \
		if (shm->exit_reason == EXIT_SIGINT) \
			exit(EXIT_FAILURE);	\
		sleep(1); \
	}\
}

#define BUG_ON(condition)	do { if ((condition)) BUG(BUGTXT); } while (0)

