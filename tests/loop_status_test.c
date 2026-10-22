/*
 * Self-check for the loop group's status-write sanitiser: a write aimed at
 * a scratch loop, by inherited fd, dup or fresh open of its node, keeps
 * LO_FLAGS_AUTOCLEAR, and any other target keeps random flags.  /dev/null
 * stands in for the node, since comparing inodes needs no loop device.
 */

#include <fcntl.h>
#include <linux/loop.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "ioctls.h"		/* struct ioctl_group */
#include "sanitise.h"		/* writable pool */
#include "scratch_block.h"	/* struct scratch_block_entry */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */

#define ROUNDS		256
#define JUNK_ARG	0xdeadbeefUL

static const struct ioctl_group *loop_grp;
static unsigned long next_request;

/* ioctls/loop.c registers its groups at load time. */
void register_ioctl_group(const struct ioctl_group *grp)
{
	if (grp->name != NULL && strcmp(grp->name, "loop") == 0)
		loop_grp = grp;
}

/* The request is the test's to choose.  The arg is one the sanitiser has
 * to replace, so a left-over one means it built no struct. */
void pick_random_ioctl(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	(void)grp;
	rec->a2 = next_request;
	rec->a3 = JUNK_ARG;
}

struct outcome {
	unsigned int autoclear;	/* struct built, flag set */
	unsigned int plain;	/* struct built, flag clear */
	unsigned int untouched;	/* no struct built */
	unsigned int status64;	/* request is LOOP_SET_STATUS64 afterwards */
};

static struct outcome run(int fd, unsigned long request)
{
	static struct syscallrecord rec;
	struct outcome o = { 0, 0, 0, 0 };
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) fd;
		next_request = request;

		loop_grp->sanitise(loop_grp, &rec);

		if (rec.a2 == LOOP_SET_STATUS64)
			o.status64++;
		if (rec.a3 == JUNK_ARG) {
			o.untouched++;
			continue;
		}
		if (((struct loop_info64 *) rec.a3)->lo_flags & LO_FLAGS_AUTOCLEAR)
			o.autoclear++;
		else
			o.plain++;
	}
	return o;
}

/* Both status requests, the old one sent down the 64-bit path, always
 * leave the flag set. */
static void flag_kept(int fd, const char *how)
{
	static const unsigned long requests[] = { LOOP_SET_STATUS64, LOOP_SET_STATUS };
	unsigned int i;

	for (i = 0; i < 2; i++) {
		struct outcome o = run(fd, requests[i]);

		if (o.plain != 0 || o.autoclear != ROUNDS || o.status64 != ROUNDS) {
			fprintf(stderr, "%s, request %#lx: %u with the flag, %u without, %u untouched, %u as LOOP_SET_STATUS64\n",
				how, requests[i], o.autoclear, o.plain,
				o.untouched, o.status64);
			BUG("loop sanitiser: a status write at a scratch loop can clear AUTOCLEAR");
		}
	}
}

/* Any other target keeps its random flag, and LOOP_SET_STATUS goes out
 * as it was picked. */
static void flag_left_random(int fd, const char *what)
{
	struct outcome o = run(fd, LOOP_SET_STATUS64);

	if (o.plain == 0 || o.autoclear == 0) {
		fprintf(stderr, "%s: %u with the flag, %u without\n",
			what, o.autoclear, o.plain);
		BUG("loop sanitiser: flags at a non-scratch target are not random");
	}

	o = run(fd, LOOP_SET_STATUS);
	if (o.untouched != ROUNDS || o.status64 != 0) {
		fprintf(stderr, "%s: LOOP_SET_STATUS: %u untouched, %u rewritten\n",
			what, o.untouched, o.status64);
		BUG("loop sanitiser: LOOP_SET_STATUS at a non-scratch target was rewritten");
	}
}

static void other_requests_untouched(int fd)
{
	static const unsigned long requests[] = {
		LOOP_GET_STATUS64, LOOP_CLR_FD, LOOP_SET_CAPACITY,
	};
	unsigned int i;

	for (i = 0; i < 3; i++) {
		struct outcome o = run(fd, requests[i]);

		if (o.untouched != ROUNDS || o.status64 != 0)
			BUG("loop sanitiser: a request that is no status write was rewritten");
	}
}

static void publish(unsigned int slot, int loop_num, int loop_fd,
		    const char *node)
{
	struct scratch_block_entry *e = &shm->isolation.scratch_block[slot];

	e->loop_num = loop_num;
	e->loop_fd = loop_fd;
	snprintf(e->dev_path, sizeof(e->dev_path), "%s", node);
}

void loop_status_self_check(void);
void loop_status_self_check(void)
{
	int node, dup_of_node, reopened, other;
	unsigned int slot;

	if (loop_grp == NULL)
		BUG("loop sanitiser: the loop group did not register");

	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	/* As create_shm() leaves them: no loop behind any slot. */
	for (slot = 0; slot < SCRATCH_BLOCK_MAX; slot++)
		publish(slot, -1, -1, "");

	node = open("/dev/null", O_RDWR);
	dup_of_node = dup(node);
	reopened = open("/dev/null", O_RDWR);
	other = open("/dev/zero", O_RDONLY);
	if (node < 0 || dup_of_node < 0 || reopened < 0 || other < 0)
		BUG("loop sanitiser: cannot open /dev/null and /dev/zero");

	flag_left_random(node, "no scratch loop published");

	/* One loop published, in each slot in turn.  The rest hold none. */
	for (slot = 0; slot < SCRATCH_BLOCK_MAX; slot++) {
		publish(slot, 3, node, "/dev/null");

		flag_kept(node, "the inherited fd");
		flag_kept(dup_of_node, "a dup");
		flag_kept(reopened, "a fresh open of the node");
		flag_left_random(other, "another device");
		flag_left_random(-1, "a closed fd");
		other_requests_untouched(node);

		/* A slot released at teardown keeps its path but no longer
		 * names a loop. */
		publish(slot, -1, -1, "/dev/null");
		flag_left_random(node, "a released slot");

		publish(slot, -1, -1, "");
	}

	memset(shm->isolation.scratch_block, 0,
	       sizeof(shm->isolation.scratch_block));
	close(node);
	close(dup_of_node);
	close(reopened);
	close(other);
}
