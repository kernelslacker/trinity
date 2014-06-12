#pragma once

#include <stdio.h>
#include <sys/types.h>
#include <types.h>
#include "syscall.h"

extern unsigned int max_children;

void child_process(int childno);
bool mkcall(void);
void do_syscall_from_child(void);

void init_child(int childno);

void reap_child(pid_t childpid);

bool child_random_syscalls(int childno);
int child_read_all_files(int childno);

void create_child_structs(void);

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
