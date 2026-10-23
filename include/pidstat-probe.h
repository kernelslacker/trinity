#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

bool pidstat_task_gone(int fd);

enum pidstat_result {
	PIDSTAT_OK,		/* buf holds the stat line */
	PIDSTAT_GONE,		/* the pid has no task */
	PIDSTAT_UNKNOWN,	/* the read failed and says nothing about the task */
};

enum pidstat_result pidstat_read(pid_t pid, char *buf, size_t size);

/*
 * What a start time reads as when /proc cannot say, as opposed to 0 for a
 * pid that is gone.  No start time equals it, so it is no proof of death:
 * pidstat_identity_gone() asks kill(pid, 0) instead.
 */
#define PID_START_TIME_UNKNOWN	(~0ULL)

struct pidstat_fields {
	char state;			/* field 3, '?' when the line has none */
	unsigned long long start_time;	/* field 22, clock ticks since boot */
};

struct pidstat_fields pidstat_parse(const char *buf);

bool pidstat_child_exited(pid_t pid);

bool pidstat_identity_gone(pid_t pid, unsigned long long start_time);
