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

	/*
	 * Per-syscall scratch slot owned by .post handlers.  Sanitise stashes
	 * a pointer or value here (typically a copy of an argN that needs to
	 * outlive .post) so the post path is immune to the argN slot being
	 * scribbled by sibling syscalls between BEFORE and AFTER.
	 */
	unsigned long post_state;

	/* timestamp (written before the syscall, and updated afterwards. */
	struct timespec tp;

	int errno_post;	/* what errno was after the syscall. */
	int rettype;	/* per-call return type (copied from entry, may be overridden by sanitise) */

	bool do32bit;
	lock_t lock;
	enum syscallstate state;
	char prebuffer[PREBUFFER_LEN];
	char postbuffer[POSTBUFFER_LEN];

	/*
	 * Wholesale-stomp detector.  Stamped with REC_CANARY_MAGIC just
	 * before the syscall is dispatched; checked on entry to
	 * handle_syscall_ret().  The snapshot pattern (post_state, plus
	 * per-handler argN shadows) defends against scribbles of individual
	 * pointer slots, but an aliased value-result write from a sibling
	 * syscall can clobber the entire syscallrecord including bookkeeping
	 * fields the snapshot pattern can't shadow.  An unchanged canary at
	 * post-handler entry rules that class out for the call; a mismatch
	 * tells us the rec was rewritten under us between BEFORE and AFTER.
	 *
	 * Trailing the postbuffer (cold tail) is deliberate: a wholesale
	 * stomp typically covers many hundreds of bytes, so a canary near
	 * the end has the highest probability of being inside the clobber
	 * region while staying off every hot cacheline.
	 */
	uint64_t _canary;
};

#define REC_CANARY_MAGIC	0xdeadbeefcafebabeULL

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

/* Per-(syscall,argnum) scoreboard of low-numbered fds (0..255) that have
 * survived a successful call.  Inline 32-byte bitmap so the whole struct
 * stays POD and lives in alloc_shared() memory -- no per-process pointers
 * (see commit e065bf1241a1 for why pointers do not work here). */
#define SUCCESS_FD_SCOREBOARD_BITS	256
#define SUCCESS_FD_SCOREBOARD_BYTES	(SUCCESS_FD_SCOREBOARD_BITS / 8)

struct results {
	/* ARG_LEN: range of successful length values. */
	bool seen;
	unsigned int min, max;
	/* ARG_FD / typed-fd: bit `fd` set if get_random_fd / get_typed_fd
	 * returned that low fd for this slot and the call succeeded. */
	unsigned char success_fds[SUCCESS_FD_SCOREBOARD_BYTES];
	/* ARG_FD / typed-fd: bit `fd` set after the same fd has failed
	 * FAIL_RUN_THRESHOLD times in a row on this slot.  fill_arg() uses
	 * it to bias re-rolls away from (slot, fd) pairs the kernel keeps
	 * rejecting (EBADF/EINVAL/etc).  Cleared by store_successful_fd(). */
	unsigned char failed_fds[SUCCESS_FD_SCOREBOARD_BYTES];
	/* Run-length tracking for the failed_fds bitmap.  Only the most
	 * recently-failing fd is tracked (full per-fd counters would cost
	 * 256 bytes per slot); good enough since we only care about long
	 * consecutive runs against a single fd, which is the actual symptom
	 * of a permanently-broken (slot, fd) pair.  fail_run_count == 0
	 * means no run in flight (so static-zero init "just works"). */
	unsigned char fail_run_fd;
	unsigned char fail_run_count;	/* saturating; 0 = no run in flight */
};

#define FAIL_RUN_THRESHOLD	3
#define FAILED_FD_REROLL_LIMIT	16

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

	/*
	 * Cached coarse syscall category (enum syscall_category, fits in a
	 * byte).  Resolved once from .name at table-init time in
	 * copy_syscall_table() so the dispatch path can index
	 * syscall_category_count[] directly instead of re-running the
	 * ~70-entry strncmp prefix scan in stats_syscall_category() on
	 * every call.
	 */
	unsigned char syscall_category;

	/*
	 * Trinity 1-based index (1..6) of the syscall argument whose value
	 * upper-bounds rec->retval -- typically the "count" / "size" / "len"
	 * argument of read/write/recv/send-class syscalls.  Consumed at the
	 * do_syscall layer by enforce_count_bound() in syscall.c, which logs
	 * any retval > rec->aN as structural ABI corruption (sign-extension
	 * tear in the return path, sibling-stomp of rec->retval, -errno
	 * leaking through the success slot, kernel write past the user
	 * bound).  Default 0 means "no bound" -- the helper short-circuits.
	 * Only annotate syscalls whose retval semantics are exactly
	 * "bytes/items processed in [0, aN] || -1" with no zero-as-query
	 * exception; iov-sum and zero-as-query syscalls stay per-syscall.
	 */
	int bound_arg;
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

void do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		struct kcov_child *kc, struct childdata *child);
void handle_syscall_ret(struct syscallrecord *rec, struct syscallentry *entry);
void generic_post_close_fd(struct syscallrecord *rec);
void post_mount_fd(struct syscallrecord *rec);

#define for_each_arg(_e, _i) \
	for (_i = 1; _i <= (_e)->num_args; _i++)

