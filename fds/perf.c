#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

#include "fd.h"
#include "list.h"
#include "objects.h"
#include "perf.h"
#include "shm.h"
#include "sanitise.h"
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

		if (head != NULL && head->list != NULL) {
			struct list_head *node, *tmp;

			list_for_each_safe(node, tmp, head->list) {
				struct object *peer = (struct object *) node;

				if (peer->perfobj.fd < 0)
					continue;
				if (peer->perfobj.group_fd != leader_fd)
					continue;
				close(peer->perfobj.fd);
				peer->perfobj.fd = -1;
			}
		}
	}

	free(obj->perfobj.eventattr);
	if (leader_fd >= 0)
		close(leader_fd);
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
		return false;
	}

	obj = alloc_object();
	obj->perfobj.fd = fd;
	obj->perfobj.eventattr = zmalloc(sizeof(struct perf_event_attr));
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

	while (i < MAX_PERF_FDS) {
		if (open_perf_fd() == true) {
			i++;
			inval_count = 0;
			perm_count = 0;
		} else {
			switch (errno) {
			case ENOSYS:
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
