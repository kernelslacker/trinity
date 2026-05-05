/* Watch-queue notification pipe FDs (pipe2(O_NOTIFICATION_PIPE)). */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

/*
 * Only the read end of an O_NOTIFICATION_PIPE pipe carries a watch_queue;
 * the write end is a normal pipe writer that the kernel uses to push
 * notification records.  We expose the read end as the OBJ_FD_WATCH_QUEUE
 * fd and keep the write end alive in peer_fd so the destructor can close
 * the pair atomically — closing the writer alone would race POLLHUP into
 * the read side and (more importantly) leak a write-end fd per regenerate
 * cycle.
 */

#ifndef O_NOTIFICATION_PIPE
#define O_NOTIFICATION_PIPE	O_EXCL
#endif
#ifndef IOC_WATCH_QUEUE_SET_SIZE
#define IOC_WATCH_QUEUE_SET_SIZE	_IO('W', 0x60)
#endif

#define WATCH_QUEUE_INIT_POOL		4
#define WATCH_QUEUE_FALLBACK_PAGES	4

static void watch_queue_destructor(struct object *obj)
{
	struct watch_queueobj *wq = &obj->watch_queueobj;

	if (wq->fd >= 0)
		close(wq->fd);
	if (wq->peer_fd >= 0)
		close(wq->peer_fd);
}

static void watch_queue_dump(struct object *obj, enum obj_scope scope)
{
	struct watch_queueobj *wq = &obj->watch_queueobj;

	output(2, "watch_queue read_fd:%d write_fd:%d scope:%d\n",
		wq->fd, wq->peer_fd, scope);
}

/*
 * Try the direct O_NOTIFICATION_PIPE flag first; fall back to a plain
 * pipe2() followed by IOC_WATCH_QUEUE_SET_SIZE.  The fallback only
 * succeeds on kernels that wired the ioctl to install a watch_queue on
 * a regular pipe; on stricter kernels the ioctl returns EOPNOTSUPP and
 * we drop the pair.  Either way a failure here is non-fatal — the pool
 * just stays smaller (or empty if every attempt fails on a kernel built
 * without CONFIG_WATCH_QUEUE).
 *
 * Returns: 0 on direct path, 1 on fallback path, -1 if both failed.
 */
static int do_watch_queue(int pipefd[2])
{
	if (pipe2(pipefd, O_NOTIFICATION_PIPE | O_CLOEXEC) == 0)
		return 0;

	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return -1;

	if (ioctl(pipefd[0], IOC_WATCH_QUEUE_SET_SIZE,
		  WATCH_QUEUE_FALLBACK_PAGES) == 0)
		return 1;

	close(pipefd[0]);
	close(pipefd[1]);
	return -1;
}

static int init_watch_queue_fds(void)
{
	struct objhead *head;
	unsigned int direct = 0, fallback = 0;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_WATCH_QUEUE);
	head->destroy = &watch_queue_destructor;
	head->dump = &watch_queue_dump;
	head->shared_alloc = true;

	for (i = 0; i < WATCH_QUEUE_INIT_POOL; i++) {
		struct object *obj;
		int pipefd[2];
		int rc;

		rc = do_watch_queue(pipefd);
		if (rc < 0)
			continue;

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL) {
			close(pipefd[0]);
			close(pipefd[1]);
			return false;
		}
		obj->watch_queueobj.fd = pipefd[0];
		obj->watch_queueobj.peer_fd = pipefd[1];
		add_object(obj, OBJ_GLOBAL, OBJ_FD_WATCH_QUEUE);

		if (rc == 0)
			direct++;
		else
			fallback++;
	}

	output(1, "watch_queue: %u direct, %u fallback (target %u).\n",
		direct, fallback, WATCH_QUEUE_INIT_POOL);

	return true;
}

static int get_rand_watch_queue_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_WATCH_QUEUE) == true)
		return -1;

	obj = get_random_object(OBJ_FD_WATCH_QUEUE, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->watch_queueobj.fd;
}

static int open_watch_queue_fd(void)
{
	struct object *obj;
	int pipefd[2];

	if (do_watch_queue(pipefd) < 0)
		return false;

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		close(pipefd[0]);
		close(pipefd[1]);
		return false;
	}
	obj->watch_queueobj.fd = pipefd[0];
	obj->watch_queueobj.peer_fd = pipefd[1];
	add_object(obj, OBJ_GLOBAL, OBJ_FD_WATCH_QUEUE);
	return true;
}

static const struct fd_provider watch_queue_fd_provider = {
	.name = "watch_queue",
	.objtype = OBJ_FD_WATCH_QUEUE,
	.enabled = true,
	.init = &init_watch_queue_fds,
	.get = &get_rand_watch_queue_fd,
	.open = &open_watch_queue_fd,
};

REG_FD_PROV(watch_queue_fd_provider);
