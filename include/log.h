#pragma once

#include <unistd.h>
#include "child.h"
#include "config.h"
#include "exit.h"
#include "shm.h"
#include "syscall.h"
#include "types.h"
#include "utils.h"

#define MAX_LOGLEVEL 3

FILE *find_logfile_handle(void);
void synclogs(void);

void output(unsigned char level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void output_syscall_prefix(struct syscallrecord *rec);
void output_syscall_postfix(struct syscallrecord *rec);
void output_rendered_buffer(char *buffer);

FILE *mainlogfile;
void open_main_logfile(void);
void close_logfile(FILE **handle);

void init_logging(void);
void shutdown_logging(void);
void init_child_logging(struct childdata *child);
void shutdown_child_logging(struct childdata *child);

void open_child_logfile(struct childdata *child);

void debugf(const char *fmt, ...);

enum {
	LOGGING_DISABLED,
	LOGGING_FILES,
};
