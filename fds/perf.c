#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>

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
		int saved_errno = errno;
		freeptr(&rec.a1);
		errno = saved_errno;
		/* No log here: failure-classification is handled by the
		 * init_perf_fds caller, which inspects errno across many
		 * attempts. Logging per call would flood. */
		return false;
	}

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		outputerr("open_perf_fd: alloc_shared_obj failed\n");
		freeptr(&rec.a1);
		close(fd);
		return false;
	}
	obj->perfobj.fd = fd;
	obj->perfobj.eventattr = alloc_shared_str(sizeof(struct perf_event_attr));
	if (obj->perfobj.eventattr == NULL) {
		outputerr("open_perf_fd: alloc_shared_str(perf_event_attr) failed\n");
		freeptr(&rec.a1);
		free_shared_obj(obj, sizeof(struct object));
		close(fd);
		return false;
	}
	memcpy(obj->perfobj.eventattr, (void *) rec.a1, sizeof(struct perf_event_attr));
	freeptr(&rec.a1);
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
	 * Route both the perfobj struct and its eventattr buffer through
	 * the shared heaps so post-fork regen via try_regenerate_fd() →
	 * open_perf_fd produces objs that already-forked children can see
	 * without chasing parent-private pointers in the destructor's
	 * free path or in any future eventattr consumer.  The buffer is
	 * the persistent obj-attached copy (sizeof(struct perf_event_attr));
	 * the larger PAGE_SIZE syscall buffer in sanitise_perf_event_open
	 * is transient — freed in the same call after memcpy — and stays
	 * on the private heap.
	 */
	head->shared_alloc = true;

	while (i < MAX_PERF_FDS) {
		if (open_perf_fd() == true) {
			i++;
			inval_count = 0;
			perm_count = 0;
		} else {
			switch (errno) {
			case ENOSYS:
				outputerr("init_perf_fds: perf_event_open returned ENOSYS (kernel lacks CONFIG_PERF_EVENTS)\n");
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
			return false;
		}

		if (inval_count > 10000) {
			output(2, "couldn't open enough perf events, got EINVAL too much. Giving up.\n");
			return false;
		}

		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
			return false;
	}

	return true;
}

int get_rand_perf_fd(void)
{
	struct object *obj;

	/* check if perf unavailable/disabled. */
	if (objects_empty(OBJ_FD_PERF) == true)
		return -1;

	obj = get_random_object(OBJ_FD_PERF, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->perfobj.fd;
}

static const struct fd_provider perf_fd_provider = {
	.name = "perf",
	.objtype = OBJ_FD_PERF,
	.enabled = true,
	.init = &init_perf_fds,
	.get = &get_rand_perf_fd,
	.open = &open_perf_fd,
};

REG_FD_PROV(perf_fd_provider);
