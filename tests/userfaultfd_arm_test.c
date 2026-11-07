/*
 * Self-check for the userfaultfd pool's handshake: every UFFDIO_API it
 * sends asks for UFFD_FEATURE_SIGBUS, some also ask for RWP, RWP_ASYNC
 * never without it, and a kernel that refuses the RWP bits is asked
 * again without them before the SIGBUS-only fallback.  The child-init
 * hook makes real user-mode-only uffds; the handshake is answered here
 * and never reaches the kernel, so no fd is armed and none registers.
 */

#include <errno.h>
#include <linux/userfaultfd.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fd.h"			/* struct fd_provider */
#include "fds/fds-internal.h"	/* fd_providers */
#include "kernel/userfaultfd.h"	/* UFFD_FEATURE_RWP, UFFD_FEATURE_RWP_ASYNC */
#include "objects.h"
#include "utils.h"		/* ARRAY_SIZE */

extern int (*fake_ioctl_hook)(int fd, unsigned long request, void *arg);	/* procfs_self_test.c */
int __real_ioctl(int fd, unsigned long request, ...);

#define RWP_BITS	(UFFD_FEATURE_RWP | UFFD_FEATURE_RWP_ASYNC)

/* uffds armed per kernel model; each asks for RWP half the time. */
#define ARMS		64

/* The kernel the handshake meets. */
static enum {
	TAKES_ALL,	/* has every feature */
	REFUSES_RWP,	/* predates RWP */
	TAKES_SIGBUS,	/* has nothing past SIGBUS */
} kernel;

/* Each UFFDIO_API's features, in the order sent. */
static __u64 asked[ARMS * 3];
static unsigned int nr_asked;

static int answer_ioctl(int fd, unsigned long request, void *arg)
{
	const struct uffdio_api *api = arg;
	bool refused;

	if (request != UFFDIO_API)
		return __real_ioctl(fd, request, arg);
	if (nr_asked == ARRAY_SIZE(asked))
		BUG("userfaultfd arm: more handshakes than three an fd");
	asked[nr_asked++] = api->features;

	refused = (kernel == REFUSES_RWP && (api->features & RWP_BITS)) ||
		  (kernel == TAKES_SIGBUS && api->features != UFFD_FEATURE_SIGBUS);
	if (refused) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static struct object objs[ARMS];
static unsigned int nr_objs;

static struct object *alloc_hook(void)
{
	if (nr_objs == ARRAY_SIZE(objs))
		BUG("userfaultfd arm: the pool took more fds than were armed");
	memset(&objs[nr_objs], 0, sizeof(objs[nr_objs]));
	return &objs[nr_objs++];
}

static void add_hook(struct object *obj, enum obj_scope scope,
		     enum objecttype type)
{
	(void) obj;
	if (scope != OBJ_LOCAL || type != OBJ_FD_USERFAULTFD)
		BUG("userfaultfd arm: an fd went into another pool");
}

/* Arm ARMS uffds through the child-init hook, which makes four a call,
 * and close them; false when this host makes none. */
static bool arm_pool(void (*child_init)(struct childdata *))
{
	static struct childdata child;
	unsigned int i;

	nr_asked = 0;
	nr_objs = 0;
	fake_ioctl_hook = answer_ioctl;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	for (i = 0; i < ARMS / 4; i++)
		child_init(&child);
	fake_ioctl_hook = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;

	for (i = 0; i < nr_objs; i++)
		close(objs[i].userfaultobj.fd);
	return nr_asked != 0;
}

/* Walk the handshakes arm by arm: each begins with a request whose
 * retries are fixed by the kernel it meets, and ends pooled. */
static void check_arms(void)
{
	unsigned int i = 0, arms = 0, rwp = 0;

	while (i < nr_asked) {
		__u64 first = asked[i++], next;

		arms++;
		if (!(first & UFFD_FEATURE_SIGBUS))
			BUG("userfaultfd arm: a handshake went without SIGBUS");
		if ((first & UFFD_FEATURE_RWP_ASYNC) && !(first & UFFD_FEATURE_RWP))
			BUG("userfaultfd arm: RWP_ASYNC was asked for without RWP");
		if (first & UFFD_FEATURE_RWP)
			rwp++;
		if (kernel == TAKES_ALL)
			continue;

		next = first;
		if (first & RWP_BITS) {
			next = first & ~RWP_BITS;
			if (i == nr_asked || asked[i++] != next)
				BUG("userfaultfd arm: refused RWP bits did not go again without them");
		}
		if (kernel == TAKES_SIGBUS && next != UFFD_FEATURE_SIGBUS &&
		    (i == nr_asked || asked[i++] != UFFD_FEATURE_SIGBUS))
			BUG("userfaultfd arm: a refused handshake did not fall back to SIGBUS alone");
	}
	if (arms != nr_objs)
		BUG("userfaultfd arm: an armed fd was not pooled");
	if (rwp == 0)
		BUG("userfaultfd arm: no handshake asked for RWP");
}

void userfaultfd_arm_self_check(void);
void userfaultfd_arm_self_check(void)
{
	void (*child_init)(struct childdata *) = NULL;
	struct list_head *node;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, "userfaultfd") == 0)
			child_init = prov->child_init;
	}
	if (child_init == NULL)
		BUG("userfaultfd arm: the userfaultfd provider is not registered");

	for (kernel = TAKES_ALL; kernel <= TAKES_SIGBUS; kernel++) {
		if (!arm_pool(child_init)) {
			printf("(no userfaultfd on this host, skipped) ");
			return;
		}
		check_arms();
	}
}
