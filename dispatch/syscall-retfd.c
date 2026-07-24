/*
 * fd return validation and registration carved out of dispatch/syscall.c.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

#include "objects.h"
#include "params.h"
#include "prop_ring.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "syscall-internal.h"
#include "syscall_record.h"
#include "tables.h"
#include "utils.h"

/*
 * Blanket retval bound for RET_FD handlers at the do_syscall layer.
 * Complements the add_object()-side check: that gate fires only on
 * RET_FD entries that declare a ret_objtype and reach the universal
 * pool-registration chokepoint.  Roughly 19 RET_FD entries instead
 * carry bespoke .post handlers that consume the returned fd without
 * ever calling add_object() -- the generic_post_close_fd users
 * (signalfd, signalfd4, fsmount, open_tree, open_tree_attr,
 * memfd_secret, pidfd_getfd), perf_event_open's close-on-fail path,
 * futex(FUTEX_FD) (which has no retval check at all), and a handful
 * of others.  Without a chokepoint at this layer a wholesale-stomped
 * or upper-bit-corrupt rec->retval whose lower bits happen to be
 * positive slips past the "(long)retval >= 0" gates these handlers
 * use and is fed straight back to the kernel as a real fd by close()
 * (or worse, lands on a file-table entry an unrelated path opened).
 *
 * 1<<20 = 1048576 matches the kernel's NR_OPEN ceiling
 * (include/uapi/linux/fs.h), the absolute upper bound RLIMIT_NOFILE
 * may be raised to on every distro we exercise.  No legitimate RET_FD
 * handler treats an out-of-range value as anything but a kernel ABI
 * violation, so the validator firing IS the bug report.
 *
 * Rettype is read via effective_rettype(): static-contract entries are
 * sourced from entry->rettype (immune to per-rec stomp), op-multiplexed
 * entries (fcntl F_DUPFD*, futex FUTEX_FD) fall through to the
 * sanitise-published rec->rettype so the per-cmd contract still applies.
 *
 * On rejection, coerce rec->retval = -1UL and rec->errno_post =
 * EINVAL.  Every existing .post handler short-circuits on
 * (long)retval < 0, register_returned_fd() likewise skips the < 0
 * branch, so the coerced shape papers over the corruption for all
 * downstream consumers in one place.  Sub-attribution by syscall
 * routes through post_handler_corrupt_ptr_bump's per-handler ring
 * via the rec it's passed; the _dispatch wrapper additionally feeds
 * this site's caller PC into the per-PC ring so the dump can tell
 * blanket-validator rejections of a syscall apart from that same
 * syscall's own .post handler rejections.
 */
bool reject_corrupt_retfd(const struct syscallentry *entry,
			  struct syscallrecord *rec)
{
	long s;

	if (effective_rettype(entry, rec) != RET_FD)
		return false;

	/* -1UL is the legitimate failure value; handle_failure path. */
	if (rec->retval == -1UL)
		return false;

	s = (long)rec->retval;
	if (s >= 0 && s < (1L << 20))
		return false;

	outputerr("retfd: rejecting out-of-bound retval=0x%lx for %s\n",
		  rec->retval, entry->name);
	post_handler_corrupt_ptr_bump_retfd(rec);
	rec->retval = -1UL;
	rec->errno_post = EINVAL;
	return true;
}

/*
 * Generic post-hook: register the fd returned by an annotated syscall
 * into its typed OBJ_LOCAL pool.  Runs after entry->post so a
 * syscall-specific handler that already registered the fd (and possibly
 * stored extra metadata like socket triplet, eventfd count, etc.)
 * stays authoritative; we only fill in what nobody else tracked.
 */
void register_returned_fd(const struct syscallentry *entry,
			  struct syscallrecord *rec)
{
	enum objecttype type = entry->ret_objtype;
	struct object *obj;
	int fd;

	if (type == OBJ_NONE)
		return;
	if ((long)rec->retval < 0)
		return;

	/* Non-fd object kinds (e.g. OBJ_KEY_SERIAL) hand off to a
	 * type-specific registrar — the fd-keyed logic below assumes
	 * an OBJ_FD_* layout (set_object_fd / find_local_object_by_fd
	 * walk fd union members) and would be a no-op otherwise. */
	if (type == OBJ_KEY_SERIAL) {
		long s = (long) rec->retval;

		if (s <= 0 || s > INT32_MAX)
			return;
		register_key_serial((int32_t) s);
		/* Mirror the key serial into the per-child prop_ring so
		 * untyped consumers in gen_undefined_arg can replay it as
		 * input to a later syscall.  prop_ring_push() above
		 * gates OBJ_NONE only, so without this bypass entry the
		 * value would never reach the ring.  Bypass is safe here:
		 * the value already cleared the (0, INT32_MAX] window
		 * register_key_serial requires, and the in-line filters
		 * inside prop_ring_push_scalar still reject pointer-shaped
		 * and fd-aliased values. */
		prop_ring_push_scalar(rec->nr, s, SCALAR_KEY_SERIAL);
		return;
	}

	if (type == OBJ_PID) {
		long p = (long) rec->retval;

		/* fork/vfork/clone parent-side success: a child pid in
		 * [1, PID_MAX_LIMIT=4194304].  Reject 0 (clone child branch
		 * already rerouted by the per-syscall .post handler that
		 * _exit's before reaching here, but defence-in-depth) and
		 * anything past the kernel's pid_max ceiling -- the latter
		 * is the corrupted-retval shape the per-syscall .post oracles
		 * already log via post_handler_corrupt_ptr_bump. */
		if (p <= 0 || p > 4194304)
			return;
		register_returned_pid((pid_t) p);
		return;
	}

	fd = (int)rec->retval;
	if (fd <= 2) {
		__atomic_add_fetch(&shm->stats.fd_runtime.stdio, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	if (find_local_object_by_fd(type, fd) != NULL) {
		__atomic_add_fetch(
			&shm->stats.fd_runtime.already_registered, 1,
			__ATOMIC_RELAXED);
		return;
	}

	obj = alloc_object();
	set_object_fd(obj, type, fd);
	add_object(obj, OBJ_LOCAL, type);

	__atomic_add_fetch(&shm->stats.fd_runtime.registered, 1,
			   __ATOMIC_RELAXED);
}
