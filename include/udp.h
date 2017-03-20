#pragma once

#include <sys/types.h>
#include <unistd.h>

#define TRINITY_LOG_PORT 6665

#define TRINITY_UDP_VERSION 0

void init_logging(char *optarg);
void shutdown_logging(void);
void sendudp(char *buffer, size_t len);

enum logmsgtypes {
	MAIN_STARTED,
	MAIN_EXITED,
};

struct msg_mainstarted {
	enum logmsgtypes type;
	pid_t pid;
	unsigned int num_children;
} msg;
