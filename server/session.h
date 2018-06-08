#pragma once

#include "child.h"

// TODO: dynamically allocate
#define MAX_CHILDREN 1024

struct fuzzsession {
	pid_t mainpid;
	unsigned int num_children;
	struct childdata children[MAX_CHILDREN];
	pthread_t decodethread;

	pthread_mutex_t packetmutex;
	struct packet mainpackets;
	int logfile;
};

extern struct fuzzsession session;
