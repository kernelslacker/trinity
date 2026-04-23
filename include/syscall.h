#pragma once

#include <time.h>
#include <sys/types.h>
#include "locks.h"
#include "object-types.h"
#include "types.h"
#include "utils.h"

#define PREBUFFER_LEN	4096
#define POSTBUFFER_LEN	128

#define MAX_NR_SYSCALL 1024

enum syscallstate {
	UNKNOWN,	/* new child */
	PREP,		/* doing sanitize */
	BEFORE,		/* about to do syscall */
	GOING_AWAY,	/* used when we don't expect to come back (execve for eg) */
	AFTER,		/* returned from doing syscall. */
};

struct syscallrecord {
	unsigned int nr;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long retval;

	/* timestamp (written before the syscall, and updated afterwards. */
	struct timespec tp;

	int errno_post;	/* what errno was after the syscall. */
	int rettype;	/* per-call return type (copied from entry, may be overridden by sanitise) */

	bool do32bit;
	lock_t lock;
	enum syscallstate state;
	char prebuffer[PREBUFFER_LEN];
	char postbuffer[POSTBUFFER_LEN];
};

enum argtype {
	ARG_UNDEFINED,
	ARG_FD,
	ARG_LEN,
	ARG_ADDRESS,
	ARG_MODE_T,
	ARG_NON_NULL_ADDRESS,
	ARG_PID,
	ARG_RANGE,
	ARG_OP,
	ARG_LIST,
	ARG_CPU,
	ARG_PATHNAME,
	ARG_IOVEC,
	ARG_IOVECLEN,
	ARG_SOCKADDR,
	ARG_SOCKADDRLEN,
	ARG_MMAP,
	ARG_SOCKETINFO,
	ARG_FD_EPOLL,
	ARG_FD_EVENTFD,
	ARG_FD_FANOTIFY,
	ARG_FD_FS_CTX,
	ARG_FD_INOTIFY,
	ARG_FD_IO_URING,
	ARG_FD_LANDLOCK,
	ARG_FD_MEMFD,
	ARG_FD_MQ,
	ARG_FD_PERF,
	ARG_FD_PIDFD,
	ARG_FD_PIPE,
	ARG_FD_SOCKET,
	ARG_FD_TIMERFD,
};

static inline bool is_typed_fdarg(enum argtype type)
{
	return type >= ARG_FD_EPOLL && type <= ARG_FD_TIMERFD;
}

static inline bool is_fdarg(enum argtype type)
{
	return type == ARG_FD || is_typed_fdarg(type);
}

struct arglist {
	unsigned int num;
	unsigned long *values;
};

#define ARGLIST(vals)		\
{				\
	.num = ARRAY_SIZE(vals),\
	.values = vals,		\
}

#define NR_ERRNOS 133	// Number in /usr/include/asm-generic/errno.h

struct results {
	/* ARG_LEN: range of successful length values. */
	bool seen;
	unsigned int min, max;
};

struct syscallentry {
	void (*sanitise)(struct syscallrecord *rec);
	void (*post)(struct syscallrecord *rec);
	int (*init)(void);
	char * (*decode)(struct syscallrecord *rec, unsigned int argnum);

	unsigned int number;
	unsigned int active_number;
	const char *name;
	const unsigned int num_args;
	unsigned int flags;

	enum argtype argtype[6];

	const char *argname[6];

	struct results results[6];

	unsigned int successes, failures, attempted;
	unsigned int errnos[NR_ERRNOS];

	/*
	 * Per-argument type-specific parameters, indexed [0..5] for args 1..6.
	 * ARG_RANGE uses .range.{low,hi}; ARG_OP/ARG_LIST uses .list.
	 * An argument can only ever be one type, so these are unioned.
	 */
	struct arg_param {
		union {
			struct { unsigned int low, hi; } range;
			struct arglist list;
		};
	} arg_params[6];

	const unsigned int group;
	const int rettype;

	/*
	 * Object type for the fd this syscall returns, or OBJ_NONE if
	 * the syscall does not return a trackable fd.  Set once in the
	 * syscallentry; the generic post-hook in handle_syscall_ret()
	 * uses it to register the returned fd into the per-type pool
	 * automatically, without each new fd-creating syscall having
	 * to write its own .post handler.
	 */
	enum objecttype ret_objtype;
};

#define RET_BORING		-1
#define RET_NONE		0
#define RET_ZERO_SUCCESS	1
#define RET_FD			2
#define RET_KEY_SERIAL_T	3
#define RET_PID_T		4
#define RET_PATH		5
#define RET_NUM_BYTES		6
#define RET_GID_T		7
#define RET_UID_T		8
#define RET_ADDRESS		9

#define GROUP_NONE	0
#define GROUP_VM	1
#define GROUP_VFS	2
#define GROUP_NET	3
#define GROUP_IPC	4
#define GROUP_PROCESS	5
#define GROUP_SIGNAL	6
#define GROUP_IO_URING	7
#define GROUP_BPF	8
#define GROUP_SCHED	9
#define GROUP_TIME	10
#define NR_GROUPS	11

struct syscalltable {
	struct syscallentry *entry;
};

#define AVOID_SYSCALL		(1<<0)
#define NI_SYSCALL		(1<<1)
#define BORING			(1<<2)
#define ACTIVE			(1<<3)
#define TO_BE_DEACTIVATED	(1<<4)
#define NEED_ALARM		(1<<5)
#define EXTRA_FORK		(1<<6)
#define IGNORE_ENOSYS		(1<<7)
#define EXPENSIVE		(1<<8)
#define NEEDS_ROOT		(1<<9)

struct kcov_child;
struct childdata;

#define LOCAL_OP_FLUSH_BATCH	1000

void do_syscall(struct syscallrecord *rec, struct kcov_child *kc, struct childdata *child);
void handle_syscall_ret(struct syscallrecord *rec);
void generic_post_close_fd(struct syscallrecord *rec);

#define for_each_arg(_e, _i) \
	for (_i = 1; _i <= (_e)->num_args; _i++)

