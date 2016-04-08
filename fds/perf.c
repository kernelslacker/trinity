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
#include "log.h"
#include "sanitise.h"

static void perffd_destructor(struct object *obj)
{
	close(obj->perffd);
}

static int open_perf_fds(void)
{
	struct objhead *head;
	unsigned int i = 0;
	unsigned int perm_count = 0;
	unsigned int inval_count = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PERF);
	head->destroy = &perffd_destructor;

	while (i < MAX_PERF_FDS) {
		struct syscallrecord *rec;
		int fd;

		rec = &shm->children[0]->syscall;
		sanitise_perf_event_open(rec);

		fd = syscall(__NR_perf_event_open, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5);
		if (fd != -1) {
			struct object *obj;

			obj = alloc_object();
			obj->perffd = fd;
			add_object(obj, OBJ_GLOBAL, OBJ_FD_PERF);

			output(2, "fd[%d] = perf\n", fd);
			i++;
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

			case EACCES:
				perm_count++;
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
	return obj->perffd;
}

const struct fd_provider perf_fd_provider = {
	.name = "perf",
	.enabled = TRUE,
	.open = &open_perf_fds,
	.get = &get_rand_perf_fd,
};
