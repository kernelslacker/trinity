#pragma once

extern unsigned char exit_reason;

enum exit_reasons {
	STILL_RUNNING = 0,
	EXIT_NO_SYSCALLS_ENABLED = 1,
	EXIT_REACHED_COUNT = 2,
	EXIT_NO_FDS = 3,
	EXIT_LOST_CHILD = 4,
	EXIT_PID_OUT_OF_RANGE = 5,
	EXIT_SIGINT = 6,
	EXIT_KERNEL_TAINTED = 7,
	EXIT_SHM_CORRUPTION = 8,
	EXIT_REPARENT_PROBLEM = 9,
	EXIT_NO_FILES = 10,
	EXIT_MAIN_DISAPPEARED = 11,
	EXIT_UID_CHANGED = 12,
	EXIT_FD_INIT_FAILURE = 13,
	EXIT_FORK_FAILURE = 14,
	EXIT_LOCKING_CATASTROPHE = 15,
	EXIT_LOGFILE_OPEN_ERROR = 16,

	NUM_EXIT_REASONS = 17
};

static const char *reasons[NUM_EXIT_REASONS] = {
  "Still running.",
  "No more syscalls enabled.",
  "Completed maximum number of operations.",
  "No file descriptors open.",
  "Lost track of a child.",
  "shm corruption - Found a pid out of range.",
  "ctrl-c",
  "kernel became tainted.",
  "SHM was corrupted!",
  "Child reparenting problem",
  "No files in file list.",
  "Main process disappeared.",
  "UID changed.",
  "Something happened during fd init.",
  "fork() failure",
  "some kind of locking catastrophe",
  "error while opening logfiles",
};

static inline const char * decode_exit(enum exit_reasons reason)
{
	return reasons[reason];
}
