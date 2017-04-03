#pragma once

#include <sys/types.h>
#include <unistd.h>
#include "exit.h"
#include "pathnames.h"
#include "types.h"

#define TRINITY_LOG_PORT 6665

#define TRINITY_UDP_VERSION 0

extern int logging_enabled;

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer, size_t len);

enum logmsgtypes {
	MAIN_STARTED,
	MAIN_EXITING,

	CHILD_SPAWNED,
	CHILD_EXITED,
	CHILD_SIGNALLED,

	OBJ_CREATED_FILE,

	MAX_LOGMSGTYPE,
};

struct msg_mainstarted {
	enum logmsgtypes type;
	pid_t pid;
	unsigned int num_children;
	void * shm_begin;
	void * shm_end;
};

struct msg_mainexiting {
	enum logmsgtypes type;
	pid_t pid;
	enum exit_reasons reason;
};

struct msg_childspawned {
	enum logmsgtypes type;
	pid_t pid;
	int childno;
};

struct msg_childexited {
	enum logmsgtypes type;
	pid_t pid;
	int childno;
};

struct msg_childsignalled {
	enum logmsgtypes type;
	pid_t pid;
	int childno;
	int sig;

};

struct msg_objcreatedfile {
	enum logmsgtypes type;
	pid_t pid;
	bool global;
	void *address;
	char filename[MAX_PATH_LEN];
	int flags;
	int fd;
	bool fopened;
	int fcntl_flags;
};
