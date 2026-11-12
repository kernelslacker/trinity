/*
 * Self-check for loop-control's sanitiser (ioctls/loop.c): LOOP_CTL_ADD
 * and LOOP_CTL_REMOVE name an index from the range the group keeps to
 * itself, so a run adds a bounded set of loop devices and removes none of
 * the host's, and the group holds both the cmd and that index.
 */

#include <linux/loop.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "syscall.h"		/* struct syscallrecord */
#include "utils-macros.h"	/* ARRAY_SIZE */

#define ROUNDS		256

/* The range ioctls/loop.c keeps, [INDEX_LO, INDEX_HI). */
#define INDEX_LO	2040UL
#define INDEX_HI	2048UL

void loop_ctl_self_check(void);
void loop_ctl_self_check(void)
{
	static const unsigned long indexed[] = { LOOP_CTL_ADD, LOOP_CTL_REMOVE };
	const struct ioctl_group *grp = fake_ioctl_group("loop-control");
	static struct syscallrecord rec;
	unsigned int i, j;

	if (grp == NULL)
		BUG("loop-control: the group did not register");
	if (!grp->cmd_held || !grp->arg_held)
		BUG("loop-control: the group does not hold its cmd and arg");

	for (j = 0; j < ARRAY_SIZE(indexed); j++) {
		fake_ioctl_request = indexed[j];
		for (i = 0; i < ROUNDS; i++) {
			memset(&rec, 0, sizeof(rec));
			grp->sanitise(grp, &rec);
			if (rec.a3 < INDEX_LO || rec.a3 >= INDEX_HI)
				BUG("loop-control: an add or remove named an index outside the reserved range");
		}
	}
}
