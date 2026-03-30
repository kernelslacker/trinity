/*
 * Struct catalog and offset mapping for CMP-guided struct filling.
 *
 * Provides a static catalog of known struct types (with per-field offset
 * and size), a table mapping syscall args to those struct types, and a
 * fast nr-indexed lookup built at init time.
 *
 * The field-for-CMP heuristic uses value magnitude to narrow which field
 * a kernel CMP constant was most likely comparing against.
 */

#include <stddef.h>
#include <string.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <time.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/io_uring.h>

#include "struct_catalog.h"
#include "arch.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* Helper: build a struct_field entry from struct S, member m. */
#define FIELD(S, m) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m) }

/* ------------------------------------------------------------------ */
/* struct timex (adjtimex, clock_adjtime)                               */
/* ------------------------------------------------------------------ */

static const struct struct_field timex_fields[] = {
	FIELD(struct timex, modes),
	FIELD(struct timex, offset),
	FIELD(struct timex, freq),
	FIELD(struct timex, maxerror),
	FIELD(struct timex, esterror),
	FIELD(struct timex, status),
	FIELD(struct timex, constant),
	FIELD(struct timex, precision),
	FIELD(struct timex, tolerance),
	FIELD(struct timex, tick),
	FIELD(struct timex, ppsfreq),
	FIELD(struct timex, jitter),
	FIELD(struct timex, shift),
	FIELD(struct timex, stabil),
	FIELD(struct timex, jitcnt),
	FIELD(struct timex, calcnt),
	FIELD(struct timex, errcnt),
	FIELD(struct timex, stbcnt),
};

/* ------------------------------------------------------------------ */
/* struct sched_attr (sched_setattr, sched_getattr)                    */
/* ------------------------------------------------------------------ */

static const struct struct_field sched_attr_fields[] = {
	FIELD(struct sched_attr, size),
	FIELD(struct sched_attr, sched_policy),
	FIELD(struct sched_attr, sched_flags),
	FIELD(struct sched_attr, sched_nice),
	FIELD(struct sched_attr, sched_priority),
	FIELD(struct sched_attr, sched_runtime),
	FIELD(struct sched_attr, sched_deadline),
	FIELD(struct sched_attr, sched_period),
	FIELD(struct sched_attr, sched_util_min),
	FIELD(struct sched_attr, sched_util_max),
};

/* ------------------------------------------------------------------ */
/* struct clone_args (clone3)                                          */
/* ------------------------------------------------------------------ */

static const struct struct_field clone_args_fields[] = {
	FIELD(struct clone_args, flags),
	FIELD(struct clone_args, pidfd),
	FIELD(struct clone_args, child_tid),
	FIELD(struct clone_args, parent_tid),
	FIELD(struct clone_args, exit_signal),
	FIELD(struct clone_args, stack),
	FIELD(struct clone_args, stack_size),
	FIELD(struct clone_args, tls),
	FIELD(struct clone_args, set_tid),
	FIELD(struct clone_args, set_tid_size),
	FIELD(struct clone_args, cgroup),
};

/* ------------------------------------------------------------------ */
/* struct io_uring_params (io_uring_setup)                             */
/* ------------------------------------------------------------------ */

static const struct struct_field io_uring_params_fields[] = {
	FIELD(struct io_uring_params, sq_entries),
	FIELD(struct io_uring_params, cq_entries),
	FIELD(struct io_uring_params, flags),
	FIELD(struct io_uring_params, sq_thread_cpu),
	FIELD(struct io_uring_params, sq_thread_idle),
	FIELD(struct io_uring_params, features),
	FIELD(struct io_uring_params, wq_fd),
};

/* ------------------------------------------------------------------ */
/* struct rlimit (setrlimit, getrlimit, prlimit64)                     */
/* ------------------------------------------------------------------ */

static const struct struct_field rlimit_fields[] = {
	FIELD(struct rlimit, rlim_cur),
	FIELD(struct rlimit, rlim_max),
};

/* ------------------------------------------------------------------ */
/* struct itimerspec (timer_settime, timerfd_settime)                  */
/* ------------------------------------------------------------------ */

static const struct struct_field itimerspec_fields[] = {
	FIELD(struct itimerspec, it_interval.tv_sec),
	FIELD(struct itimerspec, it_interval.tv_nsec),
	FIELD(struct itimerspec, it_value.tv_sec),
	FIELD(struct itimerspec, it_value.tv_nsec),
};

/* ------------------------------------------------------------------ */
/* struct epoll_event (epoll_ctl)                                      */
/* ------------------------------------------------------------------ */

static const struct struct_field epoll_event_fields[] = {
	FIELD(struct epoll_event, events),
};

/* ------------------------------------------------------------------ */
/* The catalog itself                                                   */
/* ------------------------------------------------------------------ */

const struct struct_desc struct_catalog[] = {
	{
		.name		= "timex",
		.struct_size	= sizeof(struct timex),
		.fields		= timex_fields,
		.num_fields	= ARRAY_SIZE(timex_fields),
	},
	{
		.name		= "sched_attr",
		.struct_size	= sizeof(struct sched_attr),
		.fields		= sched_attr_fields,
		.num_fields	= ARRAY_SIZE(sched_attr_fields),
	},
	{
		.name		= "clone_args",
		.struct_size	= sizeof(struct clone_args),
		.fields		= clone_args_fields,
		.num_fields	= ARRAY_SIZE(clone_args_fields),
	},
	{
		.name		= "io_uring_params",
		.struct_size	= sizeof(struct io_uring_params),
		.fields		= io_uring_params_fields,
		.num_fields	= ARRAY_SIZE(io_uring_params_fields),
	},
	{
		.name		= "rlimit",
		.struct_size	= sizeof(struct rlimit),
		.fields		= rlimit_fields,
		.num_fields	= ARRAY_SIZE(rlimit_fields),
	},
	{
		.name		= "itimerspec",
		.struct_size	= sizeof(struct itimerspec),
		.fields		= itimerspec_fields,
		.num_fields	= ARRAY_SIZE(itimerspec_fields),
	},
	{
		.name		= "epoll_event",
		.struct_size	= sizeof(struct epoll_event),
		.fields		= epoll_event_fields,
		.num_fields	= ARRAY_SIZE(epoll_event_fields),
	},
};

const unsigned int struct_catalog_count = ARRAY_SIZE(struct_catalog);

/* ------------------------------------------------------------------ */
/* Syscall -> struct arg mapping                                        */
/* ------------------------------------------------------------------ */

/*
 * Maps (syscall name, 1-based arg index) to the struct type passed at
 * that argument.  Only covers args that are struct pointers filled by
 * a custom sanitise callback.  Terminated by .syscall_name == NULL.
 */
const struct syscall_struct_arg syscall_struct_args[] = {
	/* adjtimex(struct timex *) */
	{ "adjtimex",		1, &struct_catalog[0] },
	/* clock_adjtime(clockid_t, struct timex *) */
	{ "clock_adjtime",	2, &struct_catalog[0] },
	/* sched_setattr(pid_t, struct sched_attr *, unsigned int) */
	{ "sched_setattr",	2, &struct_catalog[1] },
	/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int) */
	{ "sched_getattr",	2, &struct_catalog[1] },
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[2] },
	/* io_uring_setup(u32, struct io_uring_params *) */
	{ "io_uring_setup",	2, &struct_catalog[3] },
	/* setrlimit(unsigned int, struct rlimit *) */
	{ "setrlimit",		2, &struct_catalog[4] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[4] },
	/* prlimit64(pid_t, unsigned int, struct rlimit *, struct rlimit *) */
	{ "prlimit64",		3, &struct_catalog[4] },
	{ "prlimit64",		4, &struct_catalog[4] },
	/* timer_settime(timer_t, int, struct itimerspec *, struct itimerspec *) */
	{ "timer_settime",	3, &struct_catalog[5] },
	/* timerfd_settime(int, int, struct itimerspec *, struct itimerspec *) */
	{ "timerfd_settime",	3, &struct_catalog[5] },
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[6] },
	/* sentinel */
	{ NULL, 0, NULL },
};

/* ------------------------------------------------------------------ */
/* Fast nr -> desc lookup table                                         */
/* ------------------------------------------------------------------ */

/*
 * desc_by_nr[syscall_nr][arg_idx - 1] -> struct_desc* or NULL.
 * Populated at init time by scanning the active syscall table.
 */
static const struct struct_desc *desc_by_nr[MAX_NR_SYSCALL][6];

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; i < struct_catalog_count; i++) {
		if (strcmp(struct_catalog[i].name, name) == 0)
			return &struct_catalog[i];
	}
	return NULL;
}

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx)
{
	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	return desc_by_nr[nr][arg_idx - 1];
}

/*
 * Return the natural byte width needed to represent val:
 *   val < 2^8  -> 1, < 2^16 -> 2, < 2^32 -> 4, else 8.
 */
static unsigned int natural_width(unsigned long val)
{
	if (val < (1UL << 8))
		return 1;
	if (val < (1UL << 16))
		return 2;
	if (val < (1UL << 32))
		return 4;
	return 8;
}

int struct_field_for_cmp(const struct struct_desc *desc, unsigned long val)
{
	unsigned int want = natural_width(val);
	unsigned int i;

	/*
	 * First pass: exact size match — most specific.
	 * Second pass: any field large enough to hold the value.
	 */
	for (i = 0; i < desc->num_fields; i++) {
		if (desc->fields[i].size == want)
			return (int) i;
	}
	for (i = 0; i < desc->num_fields; i++) {
		if (desc->fields[i].size >= want)
			return (int) i;
	}
	return -1;
}

void struct_catalog_init(void)
{
	const struct syscall_struct_arg *sa;
	unsigned int i;
	int nr;

	memset(desc_by_nr, 0, sizeof(desc_by_nr));

	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx < 1 || sa->arg_idx > 6)
			continue;

		/* Search the active syscall table(s) for this name. */
		if (biarch) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				desc_by_nr[nr][sa->arg_idx - 1] = sa->desc;

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				desc_by_nr[nr][sa->arg_idx - 1] = sa->desc;
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				desc_by_nr[nr][sa->arg_idx - 1] = sa->desc;
		}
	}

	for (i = 0; i < struct_catalog_count; i++)
		output(0, "struct catalog: registered %s (%u fields, %u bytes)\n",
		       struct_catalog[i].name,
		       struct_catalog[i].num_fields,
		       struct_catalog[i].struct_size);
}
