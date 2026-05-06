#pragma once

#include "child.h"
#include "list.h"
#include "object-types.h"
#include "syscall.h"
#include "types.h"

struct epollobj;

void setup_fd_providers(void);

bool open_fds(void);

void process_fds_param(char *optarg, bool enable);

struct fd_provider {
        struct list_head list;
	const char *name;
	enum objecttype objtype;
        int (*init)(void);
        int (*get)(void);
	int (*open)(void);
	void (*child_ops)(void);	/* optional: called periodically in child context */
	bool enabled;
	bool initialized;
};

void register_fd_provider(const struct fd_provider *prov);
void dump_fd_provider_names(void);
void run_fd_provider_child_ops(void);

bool check_if_fd(struct syscallrecord *rec);

int get_random_fd(void);
int get_new_random_fd(void);
int get_typed_fd(enum argtype type);
int get_child_live_fd(struct childdata *child);
void try_regenerate_fd(enum objecttype type);

/* Defined in fds/epoll.c — child-side lazy arm.  See block comment
 * above arm_epoll() for why arming must not run in parent context. */
void arm_epoll_if_needed(struct epollobj *eo);

#define REG_FD_PROV(_struct) \
	static void __attribute__((constructor)) register_##_struct(void) { \
		register_fd_provider(&_struct); \
	}
