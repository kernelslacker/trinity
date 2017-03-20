#pragma once

#include <sys/types.h>
#include <unistd.h>
#include "exit.h"

#define TRINITY_LOG_PORT 6665

#define TRINITY_UDP_VERSION 0

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer, size_t len);

enum logmsgtypes {
	MAIN_STARTED,
	MAIN_EXITING,
	CHILD_SPAWNED,
	CHILD_EXITED,
	CHILD_SIGNALLED,
};

struct msg_mainstarted {
	enum logmsgtypes type;
	pid_t pid;
	unsigned int num_children;
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
