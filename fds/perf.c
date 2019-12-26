#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

#include "fd.h"
#include "objects.h"
#include "perf.h"
#include "shm.h"
#include "sanitise.h"
#include "utils.h"

#define MAX_PERF_FDS 10

static void perffd_destructor(struct object *obj)
{
	free(obj->perfobj.eventattr);
	close(obj->perfobj.fd);
}

static void perffd_dump(struct object *obj, bool global)
{
	struct perfobj *po = &obj->perfobj;
//	unsigned int i;

	output(2, "perf fd: %d pid:%d cpu:%d group_fd:%d flags:%lx global:%d\n",
		po->fd, po->pid, po->cpu, po->group_fd, po->flags, global);
/*	output(2, " perf_event_attr:");
	for (i = 0; i < perfsize ; i++) {
		output(CONT, "%02x ", (unsigned char) p[i]);
	}
	output(CONT, "\n");
*/
}

static int open_perf_fds(void)
{
	struct objhead *head;
	unsigned int i = 0;
	unsigned int perm_count = 0;
	unsigned int inval_count = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PERF);
	head->destroy = &perffd_destructor;
	head->dump = &perffd_dump;

	while (i < MAX_PERF_FDS) {
		struct syscallrecord *rec;
		int fd;

		rec = &shm->children[0]->syscall;
		sanitise_perf_event_open(rec);

		fd = syscall(__NR_perf_event_open, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5);
		if (fd != -1) {
			struct object *obj;

			obj = alloc_object();
			obj->perfobj.fd = fd;
			obj->perfobj.eventattr = zmalloc(sizeof(struct perf_event_attr));
			memcpy(obj->perfobj.eventattr, (void *) rec->a1, sizeof(struct perf_event_attr));
			obj->perfobj.pid = rec->a2;
			obj->perfobj.cpu = rec->a3;
			obj->perfobj.group_fd = rec->a4;
			obj->perfobj.flags = rec->a5;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_PERF);
			i++;

			/* any time we succeed, reset the failure counts.
			 * They're only there for the cases where we hit them repeatedly.
			 */
			inval_count = 0;
			perm_count = 0;
		} else {
			switch (errno) {
			case ENOSYS:
				/* If ENOSYS, bail early rather than do MAX_PERF_FDS retries */
				return FALSE;

			case EINVAL:
				/* If we get here we probably generated something invalid and
				 * perf_event_open threw it out. Go around the loop again.
				 * OR its LXCore throwing us in an endless loop.
				 */
				inval_count++;
				break;

			case EACCES:
				perm_count++;
				break;
			}
		}

		if (perm_count > 1000) {
			output(2, "Couldn't open enough perf events, got EPERM too much. Giving up.\n");
			return FALSE;
		}

		if (inval_count > 10000) {
			output(2, "couldn't open enough perf events, got EINVAL too much. Giving up.\n");
			return FALSE;
		}

		if (shm->exit_reason != STILL_RUNNING)
			return FALSE;
	}

	return TRUE;
}

int get_rand_perf_fd(void)
{
	struct object *obj;

	/* check if perf unavailable/disabled. */
	if (objects_empty(OBJ_FD_PERF) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_PERF, OBJ_GLOBAL);
	return obj->perfobj.fd;
}

static const struct fd_provider perf_fd_provider = {
	.name = "perf",
	.enabled = TRUE,
	.open = &open_perf_fds,
	.get = &get_rand_perf_fd,
};

REG_FD_PROV(perf_fd_provider);
