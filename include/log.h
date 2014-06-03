#pragma once

#include <unistd.h>
#include "exit.h"
#include "params.h"	// monochrome
#include "shm.h"
#include "types.h"

extern char ANSI_RED[];
extern char ANSI_GREEN[];
extern char ANSI_YELLOW[];
extern char ANSI_BLUE[];
extern char ANSI_MAGENTA[];
extern char ANSI_CYAN[];
extern char ANSI_WHITE[];
extern char ANSI_RESET[];

#define RED if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_RED);
#define GREEN if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_GREEN);
#define YELLOW if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_YELLOW);
#define BLUE if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_BLUE);
#define MAGENTA if (monochrome == FALSE) sptr += sprintf(sptr, "%s", ANSI_MAGENTA);
#define CYAN if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_CYAN);
#define WHITE if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_WHITE);
#define CRESET if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_RESET);

#define MAX_LOGLEVEL 3
FILE *robust_find_logfile_handle(void);
unsigned int highest_logfile(void);
void synclogs(void);
void output(unsigned char level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void output_syscall_prefix(int childno);
void output_syscall_postfix(int childno);

void open_logfiles(void);
void close_logfiles(void);
void debugf(const char *fmt, ...);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#ifndef GITVERSION
#define BUGTXT "BUG!: "
#else
#define BUGTXT "BUG!: " GITVERSION
#endif

#define BUG(bugtxt)	{ \
	printf("[%d] %s:%s:%d %s%s%s", getpid(), __FILE__, __func__, __LINE__, ANSI_RED, bugtxt, ANSI_RESET); \
	while(1) { \
		if (shm->exit_reason == EXIT_SIGINT) \
			exit(EXIT_FAILURE);	\
		sleep(1); \
	}\
}

#define BUG_ON(condition)	do { if ((condition)) BUG(BUGTXT); } while (0)

