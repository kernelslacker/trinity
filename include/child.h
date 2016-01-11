#pragma once

#include <stdio.h>
#include <sys/types.h>
#include <types.h>
#include "objects.h"
#include "syscall.h"

struct childdata {
	/* The actual syscall records each child uses. */
	struct syscallrecord syscall;

	/* log file related stuff */
	FILE *logfile;
	bool logdirty;

	/* ONLY to be read by main. */
	FILE *pidstatfile;

	struct objhead objects[MAX_OBJECT_TYPES];

	unsigned int seed;

	pid_t pid;

	unsigned int num;

	unsigned char kill_count;

	bool dontkillme;	/* provide temporary protection from the reaper. */
};

extern unsigned int max_children;

struct childdata * this_child(void);

void init_child(struct childdata *child, int childno);
void init_child_mappings(void);

void child_process(void);

void set_dontkillme(pid_t pid, bool state);

void reap_child(pid_t childpid);

bool child_random_syscalls(void);
int child_read_all_files(void);
