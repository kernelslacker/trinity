/*
 * SYSCALL_DEFINE5(perf_event_open,
	 struct perf_event_attr __user *, attr_uptr,
	 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */

#include <unistd.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include "cgroup.h"
#include "child-api.h"
#include "csfu.h"
#include "fd-event.h"
#include "maps.h"
#include "objects.h"
#include "perf.h"
#include "perf_event.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "perf_event_open-internal.h"


#include "kernel/fcntl.h"

#ifndef PERF_ATTR_SIZE_VER0
#define PERF_ATTR_SIZE_VER0	64
#endif
#ifndef PERF_ATTR_SIZE_VER1
#define PERF_ATTR_SIZE_VER1	72
#endif
#ifndef PERF_ATTR_SIZE_VER2
#define PERF_ATTR_SIZE_VER2	80
#endif
#ifndef PERF_ATTR_SIZE_VER3
#define PERF_ATTR_SIZE_VER3	96
#endif
#ifndef PERF_ATTR_SIZE_VER4
#define PERF_ATTR_SIZE_VER4	104
#endif
#ifndef PERF_ATTR_SIZE_VER5
#define PERF_ATTR_SIZE_VER5	112
#endif
#ifndef PERF_ATTR_SIZE_VER6
#define PERF_ATTR_SIZE_VER6	120
#endif
#ifndef PERF_ATTR_SIZE_VER7
#define PERF_ATTR_SIZE_VER7	128
#endif
#ifndef PERF_ATTR_SIZE_VER8
#define PERF_ATTR_SIZE_VER8	136
#endif
#ifndef PERF_ATTR_SIZE_VER9
#define PERF_ATTR_SIZE_VER9	144
#endif

/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  The kernel
 * accepts a perf_event_open call whose attr->size matches any prior
 * ABI version and zero-pads the remainder.  build_csfu_struct()
 * draws uniformly from this pool for UNDERSIZE; PERF_ATTR_SIZE_VER9
 * equals sizeof(struct perf_event_attr) on a current kernel and is
 * kept in the pool so the table stays self-documenting and remains
 * correct once the kernel grows a further ABI version.
 */
static const size_t perf_event_attr_known_sizes[] = {
	PERF_ATTR_SIZE_VER0,
	PERF_ATTR_SIZE_VER1,
	PERF_ATTR_SIZE_VER2,
	PERF_ATTR_SIZE_VER3,
	PERF_ATTR_SIZE_VER4,
	PERF_ATTR_SIZE_VER5,
	PERF_ATTR_SIZE_VER6,
	PERF_ATTR_SIZE_VER7,
	PERF_ATTR_SIZE_VER8,
	PERF_ATTR_SIZE_VER9,
};

static const struct csfu_desc desc_perf_event_attr = {
	.name = "perf_event_attr",
	.ksize = sizeof(struct perf_event_attr),
	.known_sizes = perf_event_attr_known_sizes,
	.n_known_sizes = ARRAY_SIZE(perf_event_attr_known_sizes),
};

static void pick_perf_cpu(struct syscallrecord *rec)
{
	/* cpu */
	/* requires ROOT to select specific CPU if pid==-1 (all processes) */
	/* -1 means all CPUs */

	if (RAND_BOOL()) {
		/* Any CPU */
		rec->a3 = -1;
	} else {
		/* Default to the get_cpu() value */
		/* set by ARG_CPU                 */
	}
}

static int pick_perf_group_fd(struct syscallrecord *rec)
{
	int group_leader = 0;

	/* group_fd is usually -1 or another perf_event fd.  Random non--1
	 * values mostly fail unless they name a compatible group leader,
	 * but they still exercise the kernel's validation path. */
	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a4 = -1;
		group_leader = 1;
		break;
	case 1:
		/* Try to get a previous random perf_event_open() fd  */
		rec->a4 = get_rand_perf_fd();
		break;
	case 2:
		/* Rely on ARG_FD */
		break;
	default:
		break;
	}

	return group_leader;
}

static unsigned long pick_perf_flags(void)
{
	unsigned long flags = 0;

	/* flags */
	/* You almost never set these unless you're playing with cgroups */
	if (RAND_BOOL()) {
		flags = rand64();
	} else {
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_NO_GROUP;
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_OUTPUT;
		if (RAND_BOOL())
			flags |= PERF_FLAG_PID_CGROUP;
		if (RAND_BOOL())
			flags |= PERF_FLAG_FD_CLOEXEC;
	}

	return flags;
}

static pid_t pick_perf_pid(unsigned long flags)
{
	pid_t pid;

	/* pid */
	/* requires ROOT to select pid that doesn't belong to us */

	if (flags & PERF_FLAG_PID_CGROUP) {
		/* PERF_FLAG_PID_CGROUP makes the kernel interpret 'pid' as
		 * a cgroup directory fd (an O_PATH dir under /sys/fs/cgroup).
		 * Pull from the cgroup pool so the cgroup-pinned perf path
		 * actually exercises real cgroup attachment instead of
		 * bouncing off EBADF on the first random fd we hand it.
		 * If the pool is empty (no cgroupfs mounted, init failed),
		 * fall back to a generic random fd to keep this path firing. */
		pid = get_rand_cgroup_fd();
		if (pid < 0)
			pid = get_random_fd();
	} else {
		switch(rnd_modulo_u32(4)) {
		case 0:	/* use current thread */
			pid = 0;
			break;
		case 1: /* get an arbitrary pid */
			pid = get_pid();
			break;
		case 2:	/* measure *all* pids.  Might require root */
			pid = -1;
			break;
		case 3: /* measure our actual pid */
			pid=mypid();
			break;
		default:
			pid = 0;
			break;
		}
	}

	return pid;
}

void sanitise_perf_event_open(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_perf_event_attr);
	struct perf_event_attr *attr = buf.ptr;
	unsigned long flags;
	pid_t pid;
	int group_leader;

	if (!attr)
		return;

	/*
	 * perf_event_open has no separate usize syscall arg; the kernel
	 * pulls attr->size out of the user buffer itself and drives
	 * copy_struct_from_user against that.  Plant the csfu-picked
	 * usize here so the validator gets exercised across all five
	 * bucket shapes instead of the open-coded VER0..VER8 + raw
	 * garbage roll that used to live in random_attr_size().
	 */
	attr->size = buf.usize;

	rec->a1 = (unsigned long) attr;

	/*
	 * Stash the csfu buffer in rec->post_state so the unconditional
	 * .cleanup hook frees it.  Cleanup must be independent of whether
	 * the .post handler runs: when reject_corrupt_retfd() flags retfd,
	 * handle_syscall_ret() skips .post entirely, and a post-side free
	 * would leak the snap.  post_perf_event_open does not touch
	 * post_state, so it is free to carry the buffer.
	 */
	rec->post_state = (unsigned long) attr;

	pick_perf_cpu(rec);

	group_leader = pick_perf_group_fd(rec);

	flags = pick_perf_flags();
	rec->a5 = flags;

	pid = pick_perf_pid(flags);
	rec->a2 = pid;

	maybe_fill_perf_attr_body(attr, buf.bucket, group_leader);

	avoid_shared_buffer_inout(&rec->a1, buf.usize);
}

static void post_perf_event_open(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd >= 0 && fd < (1 << 20)) {
		unsigned long flags = get_arg_snapshot(rec, 5);
		bool needs_immediate_teardown =
			(flags & (PERF_FLAG_PID_CGROUP | PERF_FLAG_FD_OUTPUT)) != 0;

		if (needs_immediate_teardown) {
			struct childdata *child = this_child();

			/*
			 * Cgroup-pinned and FD_OUTPUT-redirected events hold
			 * kernel-side references that outlive our fd: the
			 * cgroup keeps cgroup-pinned events scheduled across
			 * every task in the cgroup, and the FD_OUTPUT producer
			 * keeps writing into the consumer's ring buffer until
			 * its own deferred teardown.  Letting the dispatcher
			 * stash the fd into the OBJ_FD_PERF pool and waiting
			 * for child teardown to close it would leave both
			 * paths firing under the iteration scope of a child
			 * that may run for hours.  Walk the event off
			 * synchronously here, then coerce rec->retval = -1UL
			 * so register_returned_fd()'s (long)retval < 0 gate
			 * skips the about-to-be-closed fd -- handle_success()
			 * already ran above this layer, so the success tally
			 * is preserved.
			 */
			if (child != NULL)
				notify_child_fd_closed(child, fd);

			remove_object_by_fd(fd);

			ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
			close(fd);

			rec->retval = -1UL;
		}
		/*
		 * Common path: leave the fd open.  The dispatcher's
		 * register_returned_fd() runs after this handler and claims
		 * the fd into the OBJ_FD_PERF OBJ_LOCAL pool via the
		 * .ret_objtype annotation.  perffd_destructor handles
		 * IOC_DISABLE+close at child teardown -- and walks the pool
		 * for any peers whose group_fd matches the leader, disabling
		 * and closing those too.
		 */
	} else if (fd != -1) {
		outputerr("post_perf_event_open: rejecting out-of-bound fd=%d\n", fd);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	rec->a1 = 0;
}

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#endif

static unsigned long perf_event_open_flags[] = {
	PERF_FLAG_FD_NO_GROUP, PERF_FLAG_FD_OUTPUT, PERF_FLAG_PID_CGROUP,
	PERF_FLAG_FD_CLOEXEC,
};

static void cleanup_perf_event_open(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_perf_event_open = {
	.name = "perf_event_open",
	.num_args = 5,
	.argtype = { [0] = ARG_STRUCT_PTR_IN, [1] = ARG_PID, [2] = ARG_CPU, [3] = ARG_FD_PERF, [4] = ARG_LIST },
	.argname = { [0] = "attr_uptr", [1] = "pid", [2] = "cpu", [3] = "group_fd", [4] = "flags" },
	.arg_params[4].list = ARGLIST(perf_event_open_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_PERF,
	.sanitise = sanitise_perf_event_open,
	.post = post_perf_event_open,
	.cleanup = cleanup_perf_event_open,
	.init = init_pmus,
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.group = GROUP_PROCESS,
	/* a5 (flags) gates the synchronous-teardown decision in
	 * post_perf_event_open: PERF_FLAG_PID_CGROUP / FD_OUTPUT mark
	 * events whose kernel-side references outlive our fd and must
	 * be walked off here (rec->retval forced -1), vs. plain events
	 * left for the OBJ_FD_PERF pool to close at child teardown.
	 * Shadow a5 so a sibling stomp between dispatch and post cannot
	 * flip that gate -- leaking a pinned event into the pool, or
	 * tearing down a plain fd the caller still owns.  Mismatch
	 * bumps arg_shadow_stomp from inside get_arg_snapshot(). */
	.arg_snapshot_mask = (1u << 4),
};
