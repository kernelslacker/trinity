#pragma once

#include "list.h"
#include "types.h"

void setup_fd_providers(void);

unsigned int open_fds(void);

void process_fds_param(char *optarg, bool enable);

struct fd_provider {
        struct list_head list;
	const char *name;
        int (*open)(void);
        int (*get)(void);
	bool enabled;
};
