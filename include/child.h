#pragma once

#include <stdio.h>
#include <sys/types.h>
#include <types.h>
#include "objects.h"
#include "syscall.h"

/* Childops */
enum childtype {
	CHILD_RAND_SYSCALL,
	CHILD_READ_ALL_FILES,
	CHILD_THRASH_PID,
	CHILD_ROOT_DROP_PRIVS,
	CHILD_TRUNCATE_TESTFILE,
};

struct childdata {
	/* The actual syscall records each child uses. */
	struct syscallrecord syscall;

	/* log file related stuff */
	FILE *logfile;
	bool logdirty;

	/* ONLY to be read by main. */
	FILE *pidstatfile;

	struct objhead objects[MAX_OBJECT_TYPES];

	/* last time the child made progress. */
	struct timespec tp;
	unsigned long op_nr;

	unsigned int seed;

	unsigned int num;

	unsigned char xcpu_count;

	unsigned char kill_count;

	enum childtype type;

	bool dontkillme;	/* provide temporary protection from the reaper. */

	bool dropped_privs;
};

extern unsigned int max_children;

struct childdata * this_child(void);

void clean_childdata(struct childdata *child);

void init_child_mappings(void);

void child_process(struct childdata *child, int childno);

void set_dontkillme(struct childdata *child, bool state);

void reap_child(struct childdata *child);

void log_child_signalled(int childno, pid_t pid, int sig, unsigned long op_nr);

/* Childops */
bool random_syscall(struct childdata *child);
bool read_all_files(struct childdata *child);
bool thrash_pidfiles(struct childdata *child);
bool drop_privs(struct childdata *child);
bool truncate_testfile(struct childdata *child);
