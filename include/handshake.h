#pragma once

#include "udp.h"
#include "utils.h"

#define HELLOLEN 8

struct hellostruct {
	char hello[HELLOLEN];
	int version;
	pid_t mainpid;
	int num_children;
};

static char serverreply[] = "Trinity server v" __stringify(TRINITY_UDP_VERSION) ". Go ahead";
