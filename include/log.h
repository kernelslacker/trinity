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

FILE *find_logfile_handle(void);
void synclogs(void);

void strip_ansi(char *ansibuf);

void output(unsigned char level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void output_syscall_prefix(struct syscallrecord *rec);
void output_syscall_postfix(struct syscallrecord *rec);
void output_rendered_buffer(char *buffer);

FILE *mainlogfile;
void open_main_logfile(void);
void close_logfile(FILE **handle);

void open_child_logfile(struct childdata *child);

void debugf(const char *fmt, ...);

enum {
	LOGGING_DISABLED,
	LOGGING_FILES,
};
