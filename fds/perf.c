#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>

#include "deferred-free.h"
#include "fd.h"
#include "objects.h"
#include "perf.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#define MAX_PERF_FDS 10

/*
 * Pool entries are a mix of group leaders (group_fd == -1 at create time)
 * and members (group_fd == some pool leader's fd).  destroy_objects() walks
 * the list in insertion order and calls each entry's destructor; if a
 * leader is destroyed while one of its members is still open, the kernel
 * detaches the member from the group and re-promotes it to a standalone
 * orphan event before the member's own close arrives.  That extra
 * promote/teardown round-trip is wasted work and is not what
 * childops/perf-event-chains.c models when it explicitly closes members
 * before the leader.  Walk the rest of the pool first and pre-close any
 * members of this fd, invalidating their fd field so the outer loop's
 * later destructor invocation skips its own close().
 */
static void perffd_destructor(struct object *obj)
{
	int leader_fd = obj->perfobj.fd;

	if (leader_fd >= 0) {
		struct objhead *head = get_objhead(OBJ_GLOBAL, OBJ_FD_PERF);

		if (head != NULL && head->array != NULL) {
			struct object *peer;
			unsigned int idx;

			for_each_obj(head, peer, idx) {
				if (peer->perfobj.fd < 0)
					continue;
				if (peer->perfobj.group_fd != leader_fd)
					continue;
				ioctl(peer->perfobj.fd, PERF_EVENT_IOC_DISABLE, 0);
				/*
				 * Drop the parent_fd_hash entry for this peer
				 * before close() so a concurrent fd_hash_lookup
				 * never returns the just-closed fd.
				 * __destroy_object only removes the destroyed
				 * object's own fd; this inline pre-close path
				 * has to remove its own.  Without this, the
				 * peer's later kvm/perffd_destructor call sees
				 * fd == -1 and fd_hash_remove(-1) no-ops, so
				 * the stale entry would survive until the
				 * kernel recycled the fd number and a fresh
				 * add_object overwrote the slot.
				 */
				fd_hash_remove(peer->perfobj.fd);
				close(peer->perfobj.fd);
				peer->perfobj.fd = -1;
			}
		}
	}

	if (obj->perfobj.eventattr != NULL) {
		free_shared_str(obj->perfobj.eventattr,
				sizeof(struct perf_event_attr));
		obj->perfobj.eventattr = NULL;
	}
	if (leader_fd >= 0) {
		ioctl(leader_fd, PERF_EVENT_IOC_DISABLE, 0);
		close(leader_fd);
	}
}

static void perffd_dump(struct object *obj, enum obj_scope scope)
{
	struct perfobj *po = &obj->perfobj;

	output(2, "perf fd: %d pid:%d cpu:%d group_fd:%d flags:%lx scope:%d\n",
		po->fd, po->pid, po->cpu, po->group_fd, po->flags, scope);
}

static int open_perf_fd(void)
{
	struct syscallrecord rec;
	struct object *obj;
	int fd;

	memset(&rec, 0, sizeof(rec));
	sanitise_perf_event_open(&rec);

	fd = syscall(__NR_perf_event_open, rec.a1, rec.a2, rec.a3, rec.a4, rec.a5);
	if (fd < 0) {
		/* No log here: failure-classification is handled by the
		 * init_perf_fds caller, which inspects errno across many
		 * attempts. Logging per call would flood.  rec.a1's attr
		 * buffer is owned by the deferred-free queue (sanitise
		 * registered it via deferred_free_enqueue). */
		return false;
	}

	obj = alloc_object();
	if (obj == NULL) {
		outputerr("open_perf_fd: alloc_object failed\n");
		close(fd);
		errno = 0;
		return false;
	}
	obj->perfobj.fd = fd;
	obj->perfobj.eventattr = alloc_shared_str(sizeof(struct perf_event_attr));
	if (obj->perfobj.eventattr == NULL) {
		outputerr("open_perf_fd: alloc_shared_str(perf_event_attr) failed\n");
		tracked_free_now(obj);
		close(fd);
		errno = 0;
		return false;
	}
	/* rec.a1 carries the PAGE_SIZE attr buffer sanitise_perf_event_open
	 * allocated; on startup, if the underlying zmalloc_tracked ever
	 * comes back NULL (page-size alloc pressure during init, or a
	 * future softer-failure variant of the allocator) rec.a1 stays
	 * unset and copying from it would deref NULL.  Bail with the
	 * already-opened fd and the obj's freshly-allocated eventattr
	 * dropped through the same path the alloc-shared-str failure
	 * arm above uses. */
	if (rec.a1 == 0) {
		outputerr("open_perf_fd: sanitise produced NULL attr buf; skipping\n");
		free_shared_str(obj->perfobj.eventattr,
				sizeof(struct perf_event_attr));
		obj->perfobj.eventattr = NULL;
		tracked_free_now(obj);
		close(fd);
		errno = 0;
		return false;
	}
	memcpy(obj->perfobj.eventattr, (void *) rec.a1, sizeof(struct perf_event_attr));
	obj->perfobj.pid = rec.a2;
	obj->perfobj.cpu = rec.a3;
	obj->perfobj.group_fd = rec.a4;
	obj->perfobj.flags = rec.a5;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_PERF);
	return true;
}

static int init_perf_fds(void)
{
	struct objhead *head;
	unsigned int i = 0;
	unsigned int perm_count = 0;
	unsigned int inval_count = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PERF);
	head->destroy = &perffd_destructor;
	head->dump = &perffd_dump;
	/*
	 * The perfobj's eventattr buffer is the persistent obj-attached
	 * copy (sizeof(struct perf_event_attr)); the larger PAGE_SIZE
	 * syscall buffer in sanitise_perf_event_open is transient — freed
	 * in the same call after memcpy — and stays on the private heap.
	 */

	while (i < MAX_PERF_FDS) {
		if (open_perf_fd() == true) {
			i++;
			inval_count = 0;
			perm_count = 0;
		} else {
			switch (errno) {
			case ENOSYS:
				outputerr("init_perf_fds: perf_event_open returned ENOSYS (kernel lacks CONFIG_PERF_EVENTS)\n");
				fd_provider_init_fail(FD_INIT_REASON_CONFIG_ABSENT,
						      ENOSYS, "perf_event_open");
				return false;
			case EINVAL:
			case EMFILE:
			case ENOMEM:
			case EBUSY:
				inval_count++;
				break;
			case EACCES:
				perm_count++;
				break;
			default:
				inval_count++;
				break;
			}
		}

		if (perm_count > 1000) {
			output(2, "Couldn't open enough perf events, got EPERM too much. Giving up.\n");
			fd_provider_init_fail(FD_INIT_REASON_CAP_MISSING, EACCES,
					      "perf_event_open EACCES >1000");
			return false;
		}

		if (inval_count > 10000) {
			output(2, "couldn't open enough perf events, got EINVAL too much. Giving up.\n");
			fd_provider_init_fail(FD_INIT_REASON_ERRNO, EINVAL,
					      "perf_event_open EINVAL >10000");
			return false;
		}

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			return false;
	}

	return true;
}

int get_rand_perf_fd(void)
{
	if (objects_empty(OBJ_FD_PERF) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->perfobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the perf_event fd routed into ioctl(PERF_EVENT_IOC_*)/read via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_PERF, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PERF))
			continue;

		fd = obj->perfobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider perf_fd_provider = {
	.name = "perf",
	.objtype = OBJ_FD_PERF,
	.enabled = true,
	.init = &init_perf_fds,
	.get = &get_rand_perf_fd,
};

REG_FD_PROV(perf_fd_provider);
