#pragma once

#include <time.h>
#include <sys/types.h>
#include "locks.h"
#include "types.h"
#include "utils.h"

#define PREBUFFER_LEN	4096 * 6
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
};

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
	union {
		// ARG_FD.  -1 = Avoid. 0 = untested. 1 = Works.
		int fdmap[1024];
		// ARG_LEN
		unsigned int min, max;
	};
};

struct syscallentry {
	void (*sanitise)(struct syscallrecord *rec);
	void (*post)(struct syscallrecord *rec);
	int (*init)(void);
	char * (*decode)(struct syscallrecord *rec, unsigned int argnum);

	unsigned int number;
	unsigned int active_number;
	const char name[80];
	const unsigned int num_args;
	unsigned int flags;

	const enum argtype arg1type;
	const enum argtype arg2type;
	const enum argtype arg3type;
	const enum argtype arg4type;
	const enum argtype arg5type;
	const enum argtype arg6type;

	const char *arg1name;
	const char *arg2name;
	const char *arg3name;
	const char *arg4name;
	const char *arg5name;
	const char *arg6name;

	struct results results1;
	struct results results2;
	struct results results3;
	struct results results4;
	struct results results5;
	struct results results6;

	unsigned int successes, failures, attempted;
	unsigned int errnos[NR_ERRNOS];

	/* FIXME: At some point, if we grow more type specific parts here,
	 * it may be worth union-ising this
	 */

	/* ARG_RANGE */
	const unsigned int low1range, hi1range;
	const unsigned int low2range, hi2range;
	const unsigned int low3range, hi3range;
	const unsigned int low4range, hi4range;
	const unsigned int low5range, hi5range;
	const unsigned int low6range, hi6range;

	/* ARG_OP / ARG_LIST */
	const struct arglist arg1list;
	const struct arglist arg2list;
	const struct arglist arg3list;
	const struct arglist arg4list;
	const struct arglist arg5list;
	const struct arglist arg6list;

	const unsigned int group;
	const int rettype;
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

#define GROUP_NONE	0
#define GROUP_VM	1
#define GROUP_VFS	2

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

void do_syscall(struct syscallrecord *rec);
void handle_syscall_ret(struct syscallrecord *rec);

#define for_each_arg(_e, _i) \
	for (_i = 1; _i <= _e->num_args; _i++)

