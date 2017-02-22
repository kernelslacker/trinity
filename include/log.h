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

void output(unsigned char level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void output_syscall_prefix(struct syscallrecord *rec);
void output_syscall_postfix(struct syscallrecord *rec);
void output_rendered_buffer(char *buffer);

void debugf(const char *fmt, ...);
