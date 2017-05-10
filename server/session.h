#pragma once

#include "child.h"

// TODO: dynamically allocate
#define MAX_CHILDREN 1024

struct fuzzsession {
	pid_t mainpid;
	int num_children;
	struct childdata children[MAX_CHILDREN];
	pthread_t childthreads[MAX_CHILDREN];

	pthread_mutex_t packetmutex;
	struct packet mainpackets;
	int logfile;
};

extern struct fuzzsession session;
