#pragma once

#include <stdio.h>
#include <sys/types.h>
#include <types.h>
#include "syscall.h"

struct childdata {
	/* The actual syscall records each child uses. */
	struct syscallrecord syscall;
	struct syscallrecord previous;

	/* log file related stuff */
	FILE *logfile;
	bool logdirty;

	/* per-child mmaps */
	struct map *mappings;
	unsigned int num_mappings;

	unsigned int seed;

	pid_t pid;

	unsigned int num;

	unsigned char kill_count;

	bool dontkillme;	/* provide temporary protection from the watchdog. */
};

extern struct childdata *this_child;
extern unsigned int max_children;

void init_child(struct childdata *child, int childno);
void init_child_mappings(struct childdata *child);

void child_process(void);

void set_dontkillme(pid_t pid, bool state);

void reap_child(pid_t childpid);

bool child_random_syscalls(void);
int child_read_all_files(void);
