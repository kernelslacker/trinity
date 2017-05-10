#pragma once

#include "packet.h"

struct childdata {
	pid_t childpid;
	struct packet packets;
	pthread_mutex_t packetmutex;
	int logfile;
	unsigned long expected_seq;
	bool expecting_result;
};
