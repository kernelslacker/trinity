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
