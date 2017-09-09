#pragma once

#include "child.h"
#include "list.h"
#include "syscall.h"
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
	bool initialized;
};

void register_fd_provider(const struct fd_provider *prov);

unsigned int check_if_fd(struct childdata *child, struct syscallrecord *rec);

int get_random_fd(void);
int get_new_random_fd(void);

#define REG_FD_PROV(_struct) \
	static void __attribute__((constructor)) register_##_struct(void) { \
		register_fd_provider(&_struct); \
	}
